package tapgarden

import (
	"crypto/sha256"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/txscript"
	"github.com/lightninglabs/taproot-assets/asset"
	"github.com/lightninglabs/taproot-assets/commitment"
	"github.com/lightninglabs/taproot-assets/internal/test"
	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/stretchr/testify/require"
)

// TestGenesisScript verifies that genesisScript (batch.go:270-279) produces
// the correct PkScript for the asset anchor output in a minting transaction.
//
// Studi kasus: Tether Ltd mint 1,000,000.00 USDT sebagai stablecoin di atas
// Bitcoin (itest/most_common_usecase_test.go). Fungsi genesisScript()
// dipanggil oleh caretaker.go:644 untuk menghasilkan PkScript yang di-set
// pada anchor output (TxOut[0]) transaksi minting:
//
//	genesisScript, _ := b.cfg.Batch.genesisScript(batchSibling)
//	genesisTxPkt.UnsignedTx.TxOut[anchorOutputIndex].PkScript = genesisScript
//
// PkScript yang dihasilkan adalah P2TR (Pay-to-Taproot):
//
//	[OP_1 (0x51), OP_DATA_32 (0x20), <32-byte tweaked output key>]
//
// di mana tweaked output key = ComputeTaprootOutputKey(BatchKey.PubKey,
// TapscriptRoot[:]), dan TapscriptRoot adalah root hash dari Taproot Asset
// commitment tree yang berisi aset USDT.
//
// Catatan penting dari itest (lines 173-178): PkScript HANYA mengandung
// commitment HASH ke Taproot Asset tree. Data asli USDT (jumlah, asset ID,
// ScriptKey) hidup off-chain di proof file dan database tapd.
func TestGenesisScript(t *testing.T) {
	t.Parallel()

	// usdtMetaJSON adalah metadata compliance USDT yang sama persis
	// dengan yang digunakan di itest/most_common_usecase_test.go:69-74.
	usdtMetaJSON := []byte(
		`{"ticker":"USDT","issuer":"Tether Ltd",` +
			`"description":"Tether USD stablecoin on Bitcoin",` +
			`"website":"https://tether.to",` +
			`"compliance":"Each USDT is backed 1:1 by ` +
			`USD reserves held by Tether Ltd"}`,
	)

	// usdtAmount adalah total supply 100,000,000 unit. Dengan
	// DecimalDisplay 2, ini tampil sebagai 1,000,000.00 USDT.
	// Sama dengan itest/most_common_usecase_test.go:79.
	const usdtAmount = uint64(100000000)

	// buildUSDTAsset membuat aset USDT yang mereplikasi skenario
	// itest/most_common_usecase_test.go:
	//   - Type NORMAL (fungible, bisa split/merge)
	//   - Name "usdt"
	//   - Amount 100000000 (1,000,000.00 USDT)
	//   - MetaHash dihitung dari JSON metadata + decimal_display 2
	//   - Group key aktif (NewGroupedAsset: true)
	buildUSDTAsset := func(t *testing.T) *asset.Asset {
		t.Helper()

		// Hitung MetaHash sama seperti itest assertion 6
		// (most_common_usecase_test.go:436-441).
		meta := &proof.MetaReveal{
			Type: proof.MetaJson,
			Data: usdtMetaJSON,
		}
		err := meta.SetDecDisplay(2)
		require.NoError(t, err)
		metaHash := meta.MetaHash()

		genesis := asset.Genesis{
			FirstPrevOut: test.RandOp(t),
			Tag:          "usdt",
			MetaHash:     metaHash,
			OutputIndex:  0,
			Type:         asset.Normal,
		}

		scriptKey := asset.RandScriptKey(t)
		groupKey := asset.RandGroupKey(t, genesis, asset.NewAssetNoErr(
			t, genesis, usdtAmount, 0, 0, scriptKey, nil,
		))

		return asset.NewAssetNoErr(
			t, genesis, usdtAmount, 0, 0, scriptKey, groupKey,
		)
	}

	// buildBatchWithAssets membuat MintingBatch dengan
	// RootAssetCommitment yang di-build dari satu atau lebih aset.
	// Menggunakan batchKey yang diberikan agar caller bisa mengontrol
	// internal key (penting untuk beberapa test case).
	buildBatchWithAssets := func(t *testing.T,
		batchKey keychain.KeyDescriptor,
		assets ...*asset.Asset) *MintingBatch {

		t.Helper()

		tapCommitment, err := commitment.FromAssets(nil, assets...)
		require.NoError(t, err)

		return &MintingBatch{
			BatchKey:            batchKey,
			RootAssetCommitment: tapCommitment,
		}
	}

	// -----------------------------------------------------------------
	// Test case 1: Stablecoin mint — skenario utama USDT
	// -----------------------------------------------------------------
	// Mereplikasi alur minting USDT dari itest:
	//   1. Tether mint USDT → seedling masuk batch
	//   2. FinalizeBatch → caretaker.go:644 panggil genesisScript(nil)
	//   3. PkScript di-set pada anchor output TxOut[0]
	//
	// Sibling = nil karena minting standar tidak menggunakan tapscript
	// sibling (caretaker.go:625-626: batchSibling tetap nil jika
	// batch.tapSibling == nil).
	//
	// Verifikasi:
	//   - Format P2TR 34 bytes: [OP_1, OP_DATA_32, <32-byte key>]
	//     (sesuai itest lines 181-186)
	//   - Script = PayToTaprootScript(MintingOutputKey)
	//   - Tweaked key ≠ raw BatchKey (ada commitment tweak)
	//   - Deterministik (panggil dua kali → hasil sama)
	// -----------------------------------------------------------------
	t.Run("stablecoin_mint_anchor_script", func(t *testing.T) {
		t.Parallel()

		usdt := buildUSDTAsset(t)
		batchKey, _ := test.RandKeyDesc(t)
		batch := buildBatchWithAssets(t, batchKey, usdt)

		script, err := batch.genesisScript(nil)
		require.NoError(t, err)

		// Format P2TR: [OP_1, OP_DATA_32, <32-byte tweaked key>]
		// Sesuai itest lines 181-186:
		//   0x51 = OP_1 (witness version 1, Taproot)
		//   0x20 = OP_DATA_32 (push 32 bytes)
		//   <32 bytes> = tweaked Taproot output key
		require.Len(t, script, 34)
		require.Equal(t, byte(0x51), script[0])
		require.Equal(t, byte(0x20), script[1])

		// Verifikasi script = PayToTaprootScript(MintingOutputKey).
		// Ini mereplikasi derivation chain di caretaker.go:644:
		//   genesisScript() → MintingOutputKey() →
		//     ComputeTaprootOutputKey(BatchKey, TapscriptRoot)
		//       → PayToTaprootScript()
		outputKey, _, err := batch.MintingOutputKey(nil)
		require.NoError(t, err)
		expectedScript, err := txscript.PayToTaprootScript(
			outputKey,
		)
		require.NoError(t, err)
		require.Equal(t, expectedScript, script)

		// Tweaked key HARUS berbeda dari raw BatchKey.PubKey.
		// Ini membuktikan bahwa PkScript mengandung commitment
		// hash ke Taproot Asset tree (itest lines 173-178):
		//   "PkScript hanya mengandung commitment HASH ke
		//    Taproot Asset tree... Data asli USDT hidup off-chain"
		rawScript, err := txscript.PayToTaprootScript(
			batchKey.PubKey,
		)
		require.NoError(t, err)
		require.NotEqual(t, rawScript, script)

		// Deterministik: panggil kedua kalinya → hasil identik.
		// Penting karena caretaker menggunakan script ini untuk
		// meng-set PSBT output.
		script2, err := batch.genesisScript(nil)
		require.NoError(t, err)
		require.Equal(t, script, script2)
	})

	// -----------------------------------------------------------------
	// Test case 2: PkScript hanya berisi commitment hash, bukan data
	// USDT itu sendiri
	// -----------------------------------------------------------------
	// Dari itest lines 173-178:
	//   "Yang dikirim on-chain HANYA PkScript (tweaked pubkey 32 bytes)
	//    — bukan data USDT itu sendiri. PkScript hanya mengandung
	//    commitment HASH ke Taproot Asset tree."
	//
	// Verifikasi: 32 bytes tweaked key di PkScript[2:34] bukan
	// serialisasi raw dari BatchKey.PubKey, melainkan hasil tweak
	// dengan TapscriptRoot. Raw data USDT (amount, asset ID) tidak
	// muncul di PkScript.
	// -----------------------------------------------------------------
	t.Run("pkscript_contains_commitment_hash_not_raw_data",
		func(t *testing.T) {
			t.Parallel()

			usdt := buildUSDTAsset(t)
			batchKey, _ := test.RandKeyDesc(t)
			batch := buildBatchWithAssets(t, batchKey, usdt)

			script, err := batch.genesisScript(nil)
			require.NoError(t, err)

			tweakedKeyBytes := script[2:34]

			// Tweaked key ≠ raw batch public key (x-only,
			// 32 bytes). Jika sama, berarti tidak ada
			// commitment — fatal untuk keamanan.
			rawKeyBytes := batchKey.PubKey.
				SerializeCompressed()[1:]
			require.NotEqual(t, rawKeyBytes, tweakedKeyBytes)

			// Verifikasi bahwa tweaked key benar-benar
			// merupakan ComputeTaprootOutputKey(BatchKey,
			// TapscriptRoot). Ini membuktikan commitment
			// chain: BatchKey + TapscriptRoot → tweaked key.
			_, tapscriptRoot, err := batch.MintingOutputKey(nil)
			require.NoError(t, err)
			expectedTweakedKey :=
				txscript.ComputeTaprootOutputKey(
					batchKey.PubKey, tapscriptRoot,
				)
			expectedBytes := expectedTweakedKey.
				SerializeCompressed()[1:]
			require.Equal(t, expectedBytes, tweakedKeyBytes)

			// Pastikan tag "usdt" tidak muncul langsung di
			// PkScript. PkScript hanya berisi tweaked pubkey,
			// bukan data aset mentah.
			require.NotContains(
				t, string(script), "usdt",
				"raw asset tag should not appear "+
					"in PkScript",
			)
		})

	// -----------------------------------------------------------------
	// Test case 3: Supply berbeda → PkScript berbeda
	// -----------------------------------------------------------------
	// Jika Tether mint supply berbeda (misal 200M vs 100M unit), maka
	// commitment tree berbeda, sehingga PkScript juga berbeda. Ini
	// penting untuk proof of reserves (itest assertion 4 & 9):
	//   "Supply 100,000,000 unit... Harus persis sesuai jumlah USD
	//    reserve ($1M) yang di-back oleh Tether."
	// -----------------------------------------------------------------
	t.Run("different_supply_produces_different_script",
		func(t *testing.T) {
			t.Parallel()

			batchKey, _ := test.RandKeyDesc(t)

			// USDT 1M (100M unit) — supply standar.
			usdt1M := buildUSDTAsset(t)

			// USDT 2M (200M unit) — supply berbeda.
			// Buat genesis baru (outpoint berbeda) dengan
			// amount 200M.
			meta := &proof.MetaReveal{
				Type: proof.MetaJson,
				Data: usdtMetaJSON,
			}
			err := meta.SetDecDisplay(2)
			require.NoError(t, err)
			metaHash := meta.MetaHash()

			genesis2M := asset.Genesis{
				FirstPrevOut: test.RandOp(t),
				Tag:          "usdt",
				MetaHash:     metaHash,
				OutputIndex:  0,
				Type:         asset.Normal,
			}
			scriptKey := asset.RandScriptKey(t)
			usdt2M := asset.NewAssetNoErr(
				t, genesis2M, 200000000, 0, 0,
				scriptKey, nil,
			)

			batch1 := buildBatchWithAssets(t, batchKey, usdt1M)
			script1, err := batch1.genesisScript(nil)
			require.NoError(t, err)

			// Batch baru untuk supply 200M (batchKey sama).
			// Perlu instance terpisah karena MintingOutputKey
			// meng-cache hasil.
			batch2 := buildBatchWithAssets(t, batchKey, usdt2M)
			script2, err := batch2.genesisScript(nil)
			require.NoError(t, err)

			require.NotEqual(t, script1, script2)
		})

	// -----------------------------------------------------------------
	// Test case 4: Batch key berbeda → PkScript berbeda
	// -----------------------------------------------------------------
	// Dalam produksi, setiap batch mendapat BatchKey unik yang
	// di-derive oleh KeyRing.DeriveNextKey() (planter.go:692).
	// Dua minter berbeda (misal Tether dan Circle) yang mint USDT/USDC
	// identik tetap menghasilkan PkScript berbeda karena internal key
	// berbeda.
	//
	// Ini membuktikan bahwa PkScript = f(BatchKey, TapscriptRoot):
	//   mintingOutputKey = ComputeTaprootOutputKey(
	//     BatchKey.PubKey, TapscriptRoot[:],
	//   )
	// -----------------------------------------------------------------
	t.Run("different_batch_key_produces_different_script",
		func(t *testing.T) {
			t.Parallel()

			usdt := buildUSDTAsset(t)

			batchKey1, _ := test.RandKeyDesc(t)
			batch1 := buildBatchWithAssets(t, batchKey1, usdt)
			script1, err := batch1.genesisScript(nil)
			require.NoError(t, err)

			batchKey2, _ := test.RandKeyDesc(t)
			batch2 := buildBatchWithAssets(t, batchKey2, usdt)
			script2, err := batch2.genesisScript(nil)
			require.NoError(t, err)

			require.NotEqual(t, script1, script2)
		})

	// -----------------------------------------------------------------
	// Test case 5: Multiple aset dalam satu batch → satu PkScript
	// -----------------------------------------------------------------
	// Dari itest lines 321-323:
	//   "Semua aset dalam satu batch di-commit ke dalam satu
	//    transaksi Bitcoin (Taproot output), sehingga biaya on-chain
	//    tetap sama terlepas jumlah aset dalam batch."
	//
	// Jika Tether mint USDT dan aset lain (misal EURT) dalam satu
	// batch, keduanya di-commit ke satu Taproot output dengan satu
	// PkScript. Script dari multi-asset batch berbeda dari
	// single-asset batch.
	// -----------------------------------------------------------------
	t.Run("multi_asset_batch_single_script", func(t *testing.T) {
		t.Parallel()

		batchKey, _ := test.RandKeyDesc(t)

		// Aset 1: USDT (stablecoin utama).
		usdt := buildUSDTAsset(t)

		// Aset 2: aset lain dalam batch yang sama (misal EURT).
		eurtGenesis := asset.Genesis{
			FirstPrevOut: test.RandOp(t),
			Tag:          "eurt",
			OutputIndex:  0,
			Type:         asset.Normal,
		}
		test.RandRead(t, eurtGenesis.MetaHash[:])
		eurtScriptKey := asset.RandScriptKey(t)
		eurt := asset.NewAssetNoErr(
			t, eurtGenesis, 50000000, 0, 0,
			eurtScriptKey, nil,
		)

		// Batch dengan satu aset.
		batchSingle := buildBatchWithAssets(t, batchKey, usdt)
		scriptSingle, err := batchSingle.genesisScript(nil)
		require.NoError(t, err)

		// Batch dengan dua aset — masih menghasilkan satu
		// PkScript (satu Taproot output).
		batchMulti := buildBatchWithAssets(
			t, batchKey, usdt, eurt,
		)
		scriptMulti, err := batchMulti.genesisScript(nil)
		require.NoError(t, err)

		// Keduanya valid P2TR 34 bytes.
		require.Len(t, scriptSingle, 34)
		require.Len(t, scriptMulti, 34)

		// Tapi PkScript berbeda karena commitment tree berisi
		// aset yang berbeda.
		require.NotEqual(t, scriptSingle, scriptMulti)
	})

	// -----------------------------------------------------------------
	// Test case 6: Nil RootAssetCommitment → error
	// -----------------------------------------------------------------
	// Sebelum FinalizeBatch, RootAssetCommitment belum di-set (hanya
	// ada seedlings). Memanggil genesisScript() pada tahap ini harus
	// menghasilkan error, bukan PkScript kosong/invalid.
	// -----------------------------------------------------------------
	t.Run("nil_commitment_returns_error", func(t *testing.T) {
		t.Parallel()

		batchKey, _ := test.RandKeyDesc(t)
		batch := &MintingBatch{
			BatchKey: batchKey,
		}

		_, err := batch.genesisScript(nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "no asset commitment")
	})

	// -----------------------------------------------------------------
	// Test case 7: Metadata berbeda → PkScript berbeda
	// -----------------------------------------------------------------
	// Dari itest assertion 6 (lines 424-447): MetaHash menjadi bagian
	// dari genesis, yang mempengaruhi asset ID, yang mempengaruhi
	// commitment tree, yang mempengaruhi TapscriptRoot, yang akhirnya
	// mempengaruhi PkScript.
	//
	// Skenario: Dua stablecoin dengan metadata compliance berbeda
	// (misal issuer berbeda) menghasilkan PkScript berbeda meskipun
	// nama, supply, dan batch key sama.
	// -----------------------------------------------------------------
	t.Run("different_metadata_produces_different_script",
		func(t *testing.T) {
			t.Parallel()

			batchKey, _ := test.RandKeyDesc(t)

			// Aset 1: metadata Tether.
			meta1 := &proof.MetaReveal{
				Type: proof.MetaJson,
				Data: usdtMetaJSON,
			}
			err := meta1.SetDecDisplay(2)
			require.NoError(t, err)
			metaHash1 := meta1.MetaHash()

			genesisPoint := test.RandOp(t)
			genesis1 := asset.Genesis{
				FirstPrevOut: genesisPoint,
				Tag:          "usdt",
				MetaHash:     metaHash1,
				OutputIndex:  0,
				Type:         asset.Normal,
			}
			sk1 := asset.RandScriptKey(t)
			asset1 := asset.NewAssetNoErr(
				t, genesis1, usdtAmount, 0, 0, sk1, nil,
			)

			// Aset 2: metadata issuer berbeda (Circle).
			circleMetaJSON := []byte(
				`{"ticker":"USDT","issuer":"Circle",` +
					`"description":"USDT by Circle"}`,
			)
			metaHash2 := sha256.Sum256(circleMetaJSON)
			genesis2 := asset.Genesis{
				FirstPrevOut: genesisPoint,
				Tag:          "usdt",
				MetaHash:     metaHash2,
				OutputIndex:  0,
				Type:         asset.Normal,
			}
			sk2 := asset.RandScriptKey(t)
			asset2 := asset.NewAssetNoErr(
				t, genesis2, usdtAmount, 0, 0, sk2, nil,
			)

			batch1 := buildBatchWithAssets(t, batchKey, asset1)
			script1, err := batch1.genesisScript(nil)
			require.NoError(t, err)

			batch2 := buildBatchWithAssets(t, batchKey, asset2)
			script2, err := batch2.genesisScript(nil)
			require.NoError(t, err)

			require.NotEqual(t, script1, script2)
		})

	// -----------------------------------------------------------------
	// Test case 8: Verifikasi tapscript root tersimpan di batch
	// -----------------------------------------------------------------
	// Setelah genesisScript() dipanggil, MintingOutputKey() menyimpan
	// taprootAssetScriptRoot di batch (batch.go:200). Root ini
	// digunakan selanjutnya untuk membuat inclusion proof.
	//
	// Dari itest lines 164-167:
	//   mintingOutputKey = ComputeTaprootOutputKey(
	//     BatchKey.PubKey,      ← batch public key
	//     TapscriptRoot[:],     ← root hash dari
	//       RootAssetCommitment ← Taproot Asset commitment
	//   )
	// -----------------------------------------------------------------
	t.Run("tapscript_root_stored_after_genesis_script",
		func(t *testing.T) {
			t.Parallel()

			usdt := buildUSDTAsset(t)
			batchKey, _ := test.RandKeyDesc(t)
			batch := buildBatchWithAssets(t, batchKey, usdt)

			// Sebelum panggil genesisScript, internal cache
			// belum terisi.
			require.Nil(t, batch.mintingPubKey)
			require.Nil(t, batch.taprootAssetScriptRoot)

			_, err := batch.genesisScript(nil)
			require.NoError(t, err)

			// Setelah panggil genesisScript, MintingOutputKey
			// menyimpan hasilnya.
			require.NotNil(t, batch.mintingPubKey)
			require.NotEmpty(t, batch.taprootAssetScriptRoot)

			// TapscriptRoot yang tersimpan harus sesuai
			// dengan yang digunakan untuk tweak.
			verifyKey := txscript.ComputeTaprootOutputKey(
				batchKey.PubKey,
				batch.taprootAssetScriptRoot,
			)
			require.True(
				t, batch.mintingPubKey.IsEqual(verifyKey),
			)
		})
}

// computeTaprootOutputKeyFromBatch menghitung tweaked output key secara manual
// untuk verifikasi independen. Mereplikasi logika di batch.go:196-203:
//
//	taprootAssetScriptRoot := m.RootAssetCommitment.TapscriptRoot(nil)
//	mintingPubKey := ComputeTaprootOutputKey(BatchKey, TapscriptRoot[:])
func computeTaprootOutputKeyFromBatch(t *testing.T,
	batchKey *btcec.PublicKey,
	tapCommitment *commitment.TapCommitment) *btcec.PublicKey {

	t.Helper()

	tapscriptRoot := tapCommitment.TapscriptRoot(nil)
	return txscript.ComputeTaprootOutputKey(
		batchKey, tapscriptRoot[:],
	)
}
