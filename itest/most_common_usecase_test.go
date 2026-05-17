//go:build itest

package itest

import (
	"context"
	"encoding/hex"

	"github.com/lightninglabs/taproot-assets/proof"
	"github.com/lightninglabs/taproot-assets/taprpc"
	"github.com/lightninglabs/taproot-assets/taprpc/mintrpc"
	"github.com/stretchr/testify/require"
)

// testMostCommonUsecaseMintStablecoin memverifikasi business use case paling
// umum pada Taproot Assets: menerbitkan (mint) stablecoin di atas blockchain
// Bitcoin. Test ini mereplikasi studi kasus USDT Tether sesuai perintah CLI:
//
//	tapcli assets mint \
//	    --type normal \
//	    --name usdt \
//	    --supply 100000000 \
//	    --decimal_display 2 \
//	    --meta_bytes '{"ticker":"USDT","issuer":"Tether Ltd","website":"https://tether.to",...}' \
//	    --meta_type json \
//	    --new_grouped_asset
//
// Skenario: Tether Ltd menerbitkan 1,000,000.00 USDT (100000000 unit dengan
// decimal_display 2) yang di-back 1:1 oleh USD reserve.
//
// Setiap assertion di bawah memverifikasi aspek bisnis yang berbeda, sehingga
// test ini sekaligus berfungsi sebagai dokumentasi executable tentang apa yang
// dijamin oleh sistem saat menerbitkan stablecoin.
//
// Referensi dokumen:
//
//	taproot-asset-most-common-usecase.md, Step 2
func testMostCommonUsecaseMintStablecoin(t *harnessTest) {
	ctx := context.Background()

	// =====================================================================
	// INPUT: Definisi USDT yang akan di-mint
	// =====================================================================
	// Skenario: Tether Ltd menerbitkan batch 1,000,000.00 USDT.
	// Setiap field di bawah memiliki makna bisnis:
	//
	//   AssetType NORMAL    : USDT adalah aset fungible — 1 USDT dari
	//                         siapapun bernilai sama, dan bisa dipecah
	//                         menjadi sen ($0.01).
	//   Name "usdt"         : Identitas aset yang dikenali seluruh
	//                         ekosistem (wallet, exchange, block explorer).
	//                         Menjadi bagian dari asset ID yang unik
	//                         secara global.
	//   Amount 100000000    : Total supply = 100,000,000 unit.
	//                         Dengan DecimalDisplay 2, ini tampil sebagai
	//                         1,000,000.00 USDT di UI (satu juta dolar).
	//                         Merepresentasikan $1M USD reserve di bank.
	//   DecimalDisplay 2    : USDT menggunakan 2 desimal seperti USD
	//                         ($1.00, $0.01). 1 unit internal = $0.01.
	//   AssetMeta (JSON)    : Metadata compliance permanen: ticker,
	//                         issuer, deskripsi, website, dan backing statement.
	//                         Immutable setelah minting — siapapun bisa
	//                         memverifikasi ini adalah USDT resmi Tether.
	//   NewGroupedAsset     : Kritis untuk stablecoin. Mengaktifkan
	//                         group key sehingga Tether bisa mint USDT
	//                         tambahan (saat reserve bertambah) dan burn
	//                         (saat reserve berkurang) di masa depan.
	// =====================================================================
	jsonMetaData := []byte(
		`{"ticker":"USDT","issuer":"Tether Ltd",` +
			`"description":"Tether USD stablecoin on Bitcoin",` +
			`"website":"https://tether.to",` +
			`"compliance":"Each USDT is backed 1:1 by USD reserves held by Tether Ltd"}`,
	)
	usdtRequest := &mintrpc.MintAssetRequest{
		Asset: &mintrpc.MintAsset{
			AssetType: taprpc.AssetType_NORMAL,
			Name:      "usdt",
			Amount:    100000000,
			AssetMeta: &taprpc.AssetMeta{
				Data: jsonMetaData,
				Type: taprpc.AssetMetaType_META_TYPE_JSON,
			},
			DecimalDisplay:  2,
			NewGroupedAsset: true,
		},
	}
	mintRequests := []*mintrpc.MintAssetRequest{usdtRequest}

	// =====================================================================
	// EXECUTE: Mint + Finalize Batch + Mine Block + Verifikasi Dasar
	// =====================================================================
	// MintAssetsConfirmBatch menjalankan seluruh flow:

	//   1. MintAsset RPC     → tambahkan aset ke pending batch
	/*
		After utils.go:356 → rpcserver.go:499 MintAsset() → planter QueueNewSeedling
		→ batch.go:540, in memory:

		m.Seedlings["usdt"] = &Seedling{
			AssetVersion: asset.V0,
			AssetType:    asset.Normal,
			AssetName:    "usdt",
			Amount:       100000000,
			EnableEmission: true,
			Meta: &proof.MetaReveal{
				Type: proof.MetaJson,
				Data: []byte(`{"compliance":"Each USDT is backed 1:1 by USD reserves held by Tether Ltd","decimal_display":2,"description":"Tether USD stablecoin on Bitcoin","issuer":"Tether Ltd","ticker":"USDT","website":"https://tether.to"}`),
				DecimalDisplay: fn.Some[uint32](2),
			},
		}

		Perhatikan transformasi Meta.Data:
		- Input  : key order sesuai penulisan, tanpa decimal_display
		- Output : key sorted alfabetis (json.Marshal pada map),
		           decimal_display:2 disisipkan oleh rpcserver.go:637
		           SetDecDisplay() → meta.go:451 → EncodeMetaJSON()
	*/

	//   2. FinalizeBatch RPC → buat transaksi Bitcoin, broadcast
	//      Call chain:
	//        rpcserver.go:980   RPCServer.FinalizeBatch()
	//          → planter.go:2086  ChainPlanter.finalizeBatch()
	//            → caretaker.go:160  BatchCaretaker.Start()
	//              → caretaker.go:358  assetCultivator() state machine loop
	//
	//      Konstruksi & signing transaksi Bitcoin (state BatchStateCommitted):
	//        caretaker.go:713  Wallet.SignAndFinalizePsbt() — wallet LND sign PSBT
	//        caretaker.go:721  psbt.Extract() — ekstrak signed tx dari PSBT
	//        caretaker.go:726  CheckTransactionSanity() — validasi final
	//
	//      Broadcast transaksi ke network (state BatchStateBroadcast):
	//        caretaker.go:849  ChainBridge.PublishTransaction()
	//          → chain_bridge.go:331  lnd.WalletKit.PublishTransaction()
	//              — panggilan RPC ke LND yang broadcast tx ke Bitcoin network
	/*
		tapgarden/caretaker.go:849 → lndservices/chain_bridge.go:331 function call parameters:
			signedTx = &wire.MsgTx{
				Version:  2,
				LockTime: 0,
				TxIn: []*wire.TxIn{
					{
						PreviousOutPoint: wire.OutPoint{
							// Runtime: txid UTXO dari lnd wallet,
							// didapat saat FundPsbt (planter.go:1067).
							// Bukan all-zeros (itu coinbase reference).
							Hash:  [32]byte{<lnd wallet UTXO txid>},
							Index: <lnd wallet UTXO output index>,
						},
						Sequence: 0xffffffff,
					},
				},
				TxOut: []*wire.TxOut{
					// [anchorOutputIndex=0] Asset anchor output (Taproot/P2TR)
					// TUJUAN: MINTER SENDIRI (self-spend).
					//   BatchKey di-derive oleh tapd minter via
					//   KeyRing.DeriveNextKey() (planter.go:692),
					//   disimpan di key store minter.
					// PkScript di-set oleh caretaker.go:650-651:
					//   genesisScript() (batch.go:278)
					//     → txscript.PayToTaprootScript(mintingOutputKey)
					//   mintingOutputKey dihitung oleh batch.go:201:
					//     txscript.ComputeTaprootOutputKey(
					//       BatchKey.PubKey,            ← batch public key
					//       TapscriptRoot[:],           ← root hash dari
					//         RootAssetCommitment tree  ← Taproot Asset commitment
					//     )
					// CATATAN: Tidak ada field "address" di wire.MsgTx.
					//   "Address" (bcrt1p...) adalah derivasi eksternal
					//   dari PkScript oleh wallet/explorer:
					//     PkScript[2:34] → bech32m → "bcrt1p..."
					//   Yang dikirim on-chain HANYA PkScript di atas.
					//   Bitcoin node biasa hanya melihat 1000 sats
					//   di P2TR output; tidak tahu ada aset USDT.
					{
						Value: 1000, // DummyAmtSats (tapsend/send.go:42)
						PkScript: []byte{
							0x51, // OP_1 (witness version 1, Taproot)
							0x20, // OP_DATA_32 (push 32 bytes)
							// <32-byte tweaked Taproot output key
							//  yang meng-commit ke asset tree>
						}, // total 34 bytes (P2TR script)
					},
					// [changeOutputIndex=1] Change output
					// TUJUAN: MINTER SENDIRI (lnd wallet).
					//   Sisa sats dikembalikan ke lnd wallet minter.
					//   Ditambahkan oleh lnd FundPsbt (planter.go:1067).
					//   Wajib ada: planter.go:1073 cek ChangeOutputIndex != -1.
					// CATATAN: Tidak ada field "address" di wire.MsgTx.
					//   "Address" hanya derivasi eksternal dari PkScript.
					{
						Value:    <sisa sats setelah anchor + fee>,
						PkScript: []byte{<lnd wallet change script>},
					},
					//
					// Kesimpulan: KEDUA output milik minter sendiri.
					// Minting = self-spend. Distribusi USDT ke pihak
					// lain (exchange, user) dilakukan via operasi
					// send/transfer terpisah (bukan di transaksi ini).
				},
			}

			IssuanceTxLabel = "tapd-asset-issuance" // tapgarden/interface.go:29

		Contoh runtime (regtest itest, nilai spesifik berubah tiap run):

			signedTx = &wire.MsgTx{
				Version:  2,
				LockTime: 0,
				TxIn: []*wire.TxIn{
					{
						// UTXO dari lnd wallet Alice (didanai
						// oleh NewNodeWithCoins → mining regtest).
						// Input ini ber-witness P2TR (mock.go:375-382).
						PreviousOutPoint: wire.OutPoint{
							Hash: chainhash.Hash{
								0xa3, 0x1b, 0x7c, 0x0e,
								0x4f, 0xd2, 0x88, 0x91,
								0x6c, 0x5a, 0xf7, 0x3b,
								0xe1, 0x09, 0xd4, 0x72,
								0x8e, 0x63, 0x01, 0xab,
								0xf5, 0xc4, 0xde, 0x97,
								0x2b, 0x83, 0x44, 0x56,
								0x10, 0xfa, 0xcd, 0x38,
							},
							Index: 1,
						},
						Sequence: 0xffffffff,
					},
				},
				TxOut: []*wire.TxOut{
					// [0] Asset anchor (P2TR) → MINTER SENDIRI
					//     1000 sats = DummyAmtSats, cukup di atas dust limit.
					//     PkScript = PayToTaprootScript(mintingOutputKey).
					//     mintingOutputKey = ComputeTaprootOutputKey(
					//       BatchKey.PubKey, TapscriptRoot,
					//     ) → batch.go:201
					//     Tidak ada field "address" di wire.MsgTx.
					//     PkScript[2:] → bech32m (oleh wallet/explorer)
					//       → "bcrt1p..." (di luar data transaksi)
					//     Tersembunyi di dalam PkScript: 1,000,000.00 USDT
					{
						Value: 1000,
						PkScript: []byte{
							0x51, 0x20, // OP_1 OP_DATA_32
							0xb7, 0x2e, 0x91, 0xa5,
							0x03, 0xf8, 0x6c, 0xd1,
							0x4b, 0x7a, 0xe2, 0x8f,
							0x30, 0x9e, 0x01, 0xc4,
							0xd7, 0x15, 0xbe, 0x09,
							0x8a, 0x6c, 0x51, 0xf7,
							0xe0, 0x22, 0xf3, 0xd8,
							0x94, 0x1d, 0xe6, 0x4a,
						}, // 34 bytes total
					},
					// [1] Change (witness v0, P2WSH-like) → MINTER SENDIRI
					//     Sisa sats dikembalikan ke lnd wallet Alice.
					//     mock.go:388 → anchorBalance(100000) - anchor(1000) = 99000
					//     mock.go:401 → 99000 - fee(~250) = ~98750
					//     PkScript: copy GenesisDummyScript, ganti byte[0]
					//     ke OP_0 (mock.go:391). Sengaja non-P2TR agar
					//     tidak perlu generate exclusion proof (mock.go:385).
					{
						Value: 98750,
						PkScript: []byte{
							0x00, 0x20, // OP_0 OP_DATA_32
							0xd8, 0x5c, 0xa1, 0x33,
							0x07, 0xef, 0x2b, 0x69,
							0x44, 0x8e, 0xf1, 0xc2,
							0x78, 0xb0, 0x56, 0xa3,
							0x9c, 0x71, 0xd0, 0x42,
							0x6a, 0x93, 0x08, 0xbb,
							0xe5, 0x19, 0x7f, 0xa4,
							0x11, 0x60, 0xc3, 0x7f,
						}, // 34 bytes total
					},
				},
			}
	*/

	//   3. Mine 1 block      → konfirmasi transaksi on-chain
	//      Call chain (sisi test — trigger mining):
	//        utils.go:567  ConfirmBatch() → MineBlocks(t, minerClient, 1, 1)
	//        utils.go:211  minerClient.GenerateBlocks(1) → btcd mine 1 block
	//
	//      Call chain (sisi tapd — deteksi konfirmasi):
	//        caretaker.go:867  ChainBridge.RegisterConfirmationsNtfn()
	//          → chain_bridge.go:80  lnd.ChainNotifier.RegisterConfirmationsNtfn()
	//              — subscribe ke LND untuk notifikasi konfirmasi tx
	//        caretaker.go:892  <-confNtfn.Confirmed
	//              — goroutine menerima event konfirmasi dari LND
	//        caretaker.go:941  b.confEvent <- confEvent
	//              — kirim event ke assetCultivator loop
	//
	//      Call chain (sisi tapd — transisi state ke FINALIZED):
	//        caretaker.go:383  <-b.confEvent (assetCultivator menerima konfirmasi)
	//        caretaker.go:389  Batch.UpdateState(BatchStateConfirmed)
	//        caretaker.go:393  advanceStateUntil(Confirmed, BatchStateFinalized)
	//              — generate proof files, commit ke database
	//        caretaker.go:405  SignalCompletion() → batch selesai
	//
	//      Verifikasi oleh test:
	//        utils.go:569  WaitForBatchState(BATCH_STATE_FINALIZED)
	//          → assertions.go:437  polling ListBatches sampai state FINALIZED
	//

	//   4. AssertAssetsMinted → verifikasi aset ter-mint dengan benar

	//
	// Catatan arsitektur: Semua aset dalam satu batch di-commit ke dalam
	// satu transaksi Bitcoin (Taproot output), sehingga biaya on-chain
	// tetap sama terlepas jumlah aset dalam batch.
	//
	// Koneksi ke eksternal 3rd party: TIDAK ADA.
	// Semua koneksi bersifat lokal antar komponen test harness:
	//   test → tapd (gRPC localhost) → lnd (gRPC localhost) → btcd (regtest lokal)
	// Proof courier / universe server TIDAK diaktifkan saat minting.
	// Courier hanya digunakan saat transfer/send aset ke penerima.
	//
	// Inisialisasi binary (btcd, lnd, tapd) untuk integration test:
	//
	// 1. Build: `make itest` compile 3 binary ke folder itest/
	//      Makefile:139  → itest/btcd-itest (github.com/btcsuite/btcd)
	//      Makefile:142  → itest/lnd-itest  (lnd/cmd/lnd)
	//      Makefile:148  → itest/tapd-itest (taproot-assets/cmd/tapd)
	//
	// 2. Entry point: integration_test.go:62 TestTaprootAssetsDaemon()
	//      integration_test.go:83  lntest.SetupHarness("./lnd-itest")
	//        → start btcd-itest sebagai OS process (via -btcdexec flag)
	//        → buat blockchain regtest
	//        → start lnd-itest sebagai OS process (root node)
	//
	// 3. Per-test setup: integration_test.go:122 setupHarnesses()
	//      → test_harness.go:260  setupHarnesses()
	//        → lndHarness.NewNode("uni-server-lnd")  → lnd OS process
	//        → newUniverseServerHarness()             → tapd-itest OS process
	//        → lndHarness.NewNodeWithCoins("Alice")   → lnd OS process
	//        → setupTapdHarness()                     → tapd-itest OS process
	//
	// 4. tapd-itest start: tapd_harness.go:614
	//      :616  exec.Command("./tapd-itest", args...) → spawn OS process
	//      :624  cmd.Start()
	//      :646  wait.NoError(net.Dial("tcp", rpcAddr)) → tunggu gRPC ready
	//      :662  taprpc.NewTaprootAssetsClient(rpcConn) → buat gRPC client
	//
	// Diagram OS processes saat test berjalan (semua localhost, regtest):
	//
	//   btcd-itest (miner)
	//       ↑ RPC
	//   lnd-itest (uni-server)     lnd-itest (Alice)
	//       ↑ gRPC                     ↑ gRPC
	//   tapd-itest (universe svr)  tapd-itest (t.tapd, client)
	//                                  ↑ gRPC
	//                              go test (test code)
	// =====================================================================
	rpcAssets := MintAssetsConfirmBatch(
		t.t, t.lndHarness.Miner(), t.tapd, mintRequests,
	)

	// =====================================================================
	// ASSERTION 1: Mint menghasilkan tepat 1 aset
	// =====================================================================
	// Bisnis: Satu perintah mint menghasilkan satu aset. Jika lebih atau
	// kurang, ada masalah pada batch processing.
	// =====================================================================
	require.Len(t.t, rpcAssets, 1)
	mintedAsset := rpcAssets[0]

	// =====================================================================
	// ASSERTION 2: Nama aset sesuai dengan yang diminta
	// =====================================================================
	// Bisnis: Nama "usdt" adalah identitas yang dikenali seluruh ekosistem
	// dan menjadi bagian dari asset ID (genesis hash). Nama yang salah
	// berarti aset yang berbeda secara kriptografis — wallet dan exchange
	// tidak akan mengenalinya sebagai USDT.
	// =====================================================================
	require.Equal(t.t, "usdt", mintedAsset.AssetGenesis.Name)

	// =====================================================================
	// ASSERTION 3: Tipe aset adalah NORMAL (fungible)
	// =====================================================================
	// Bisnis: USDT harus NORMAL (fungible) — bisa dipecah (split) dan
	// digabung (merge). User harus bisa mengirim $0.01 dari total
	// $1,000,000.00. Berbeda dengan COLLECTIBLE (NFT, amount selalu 1).
	// =====================================================================
	require.Equal(
		t.t, taprpc.AssetType_NORMAL,
		taprpc.AssetType(mintedAsset.AssetGenesis.AssetType),
	)

	// =====================================================================
	// ASSERTION 4: Supply (amount) sesuai dengan yang diminta
	// =====================================================================
	// Bisnis: Supply 100,000,000 unit dengan decimal_display 2 =
	// 1,000,000.00 USDT. Harus persis sesuai jumlah USD reserve ($1M)
	// yang di-back oleh Tether. Selisih 1 unit pun berarti mismatch
	// antara on-chain supply dan bank reserve.
	// =====================================================================
	require.Equal(t.t, uint64(100000000), mintedAsset.Amount)

	// =====================================================================
	// ASSERTION 5: Decimal display sesuai dengan yang diminta
	// =====================================================================
	// Bisnis: USDT menggunakan 2 desimal seperti USD ($1.00, $0.01).
	// Dengan decimal_display=2, jumlah 100000000 ditampilkan sebagai
	// 1,000,000.00 USDT. Salah setting (mis. 3 desimal) menyebabkan
	// wallet menampilkan $100,000.000 — membingungkan user.
	// =====================================================================
	require.NotNil(t.t, mintedAsset.DecimalDisplay)
	require.EqualValues(t.t, 2, mintedAsset.DecimalDisplay.DecimalDisplay)

	// =====================================================================
	// ASSERTION 6: Metadata JSON valid dan meta hash konsisten
	// =====================================================================
	// Bisnis: Metadata melekat permanen pada USDT (immutable). Hash-nya
	// menjadi bagian dari genesis, sehingga metadata tidak bisa diubah
	// setelah minting. Siapapun (auditor, regulator, user) bisa
	// memverifikasi bahwa USDT ini benar diterbitkan oleh "Tether Ltd"
	// dengan backing statement yang tercatat on-chain secara trustless.
	//
	// Teknis: Meta hash dihitung dari JSON data + decimal display yang
	// di-encode ke dalam metadata. Kita memverifikasi bahwa hash yang
	// dikembalikan RPC cocok dengan perhitungan manual.
	// =====================================================================
	expectedMeta := &proof.MetaReveal{
		Type: proof.MetaJson,
		Data: jsonMetaData,
	}
	err := expectedMeta.SetDecDisplay(2)
	require.NoError(t.t, err)

	expectedMetaHash := expectedMeta.MetaHash()
	require.Equal(
		t.t, expectedMetaHash[:],
		mintedAsset.AssetGenesis.MetaHash,
	)

	// Verifikasi bahwa metadata bisa di-fetch dan berisi informasi
	// compliance USDT yang benar.
	metaResp, err := t.tapd.FetchAssetMeta(
		ctx, &taprpc.FetchAssetMetaRequest{
			Asset: &taprpc.FetchAssetMetaRequest_AssetId{
				AssetId: mintedAsset.AssetGenesis.AssetId,
			},
		},
	)
	require.NoError(t.t, err)
	require.Equal(
		t.t, taprpc.AssetMetaType_META_TYPE_JSON, metaResp.Type,
	)
	require.Contains(t.t, string(metaResp.Data), `"ticker":"USDT"`)
	require.Contains(t.t, string(metaResp.Data), `"issuer":"Tether Ltd"`)
	require.Contains(t.t, string(metaResp.Data), `stablecoin on Bitcoin`)
	require.Contains(t.t, string(metaResp.Data), `"website":"https://tether.to"`)
	require.Contains(t.t, string(metaResp.Data), `backed 1:1 by USD reserves held by Tether Ltd`)
	require.Equal(t.t, uint32(2), metaResp.DecimalDisplay)

	// =====================================================================
	// ASSERTION 7: Group key ada (re-issuance diaktifkan)
	// =====================================================================
	// Bisnis: Kritis untuk USDT. Group key memungkinkan Tether mencetak
	// USDT tambahan kapan saja (saat USD reserve bertambah) dan burn
	// (saat reserve berkurang). Tanpa ini, supply fixed selamanya —
	// tidak cocok untuk stablecoin yang harus dinamis.
	//
	// Teknis: Group key adalah public key identifier grup. Semua USDT
	// (batch awal + re-issuance berikutnya) berbagi group key yang sama,
	// sehingga wallet bisa memverifikasi semuanya berasal dari Tether.
	// =====================================================================
	require.NotNil(t.t, mintedAsset.AssetGroup)
	require.NotEmpty(t.t, mintedAsset.AssetGroup.TweakedGroupKey)

	// Verifikasi grup terdaftar di ListGroups dan berisi tepat 1 aset.
	groupKeyHex := hex.EncodeToString(
		mintedAsset.AssetGroup.TweakedGroupKey,
	)
	AssertGroupSizes(t.t, t.tapd, []string{groupKeyHex}, []int{1})

	// =====================================================================
	// ASSERTION 8: Proof file valid
	// =====================================================================
	// Bisnis: Proof adalah bukti kriptografis kepemilikan USDT. Tanpa
	// proof yang valid, exchange tidak bisa memverifikasi bahwa USDT
	// benar-benar ada dan dimiliki oleh Tether. Proof system adalah
	// fondasi trust model — exchange tidak perlu percaya Tether, cukup
	// verifikasi proof secara matematis.
	//
	// Catatan teknis: Tidak menggunakan AssertMintingProofs karena fungsi
	// tersebut melakukan perbandingan exact byte pada metadata. Untuk JSON
	// metadata dengan DecimalDisplay, sistem melakukan canonicalization
	// (sort keys alfabetis) dan menyisipkan "decimal_display":N ke dalam
	// JSON, sehingga byte output berbeda dari byte input. Kita melakukan
	// verifikasi proof secara manual: export, verify, decode.
	// =====================================================================
	exportResp, err := t.tapd.ExportProof(
		ctx, &taprpc.ExportProofRequest{
			AssetId:   mintedAsset.AssetGenesis.AssetId,
			ScriptKey: mintedAsset.ScriptKey,
		},
	)
	require.NoError(t.t, err)

	verifyResp, err := t.tapd.VerifyProof(ctx, &taprpc.ProofFile{
		RawProofFile: exportResp.RawProofFile,
	})
	require.NoError(t.t, err)
	require.True(t.t, verifyResp.Valid)

	decodeResp, err := t.tapd.DecodeProof(
		ctx, &taprpc.DecodeProofRequest{
			RawProof:       exportResp.RawProofFile,
			WithMetaReveal: true,
		},
	)
	require.NoError(t.t, err)
	require.NotNil(t.t, decodeResp.DecodedProof.MetaReveal)
	require.Equal(
		t.t, taprpc.AssetMetaType_META_TYPE_JSON,
		decodeResp.DecodedProof.MetaReveal.Type,
	)
	proofMeta := string(decodeResp.DecodedProof.MetaReveal.Data)
	require.Contains(t.t, proofMeta, `"ticker":"USDT"`)
	require.Contains(t.t, proofMeta, `"issuer":"Tether Ltd"`)
	require.Contains(t.t, proofMeta, `"website":"https://tether.to"`)
	require.Contains(t.t, proofMeta, `backed 1:1 by USD reserves held by Tether Ltd`)
	require.Contains(t.t, proofMeta, `"decimal_display":2`)

	// =====================================================================
	// ASSERTION 9: Balance tercatat dengan benar
	// =====================================================================
	// Bisnis: Setelah minting, saldo Tether harus = 1,000,000.00 USDT
	// (100000000 unit). Ini penting untuk:
	//   - Proof of reserves: auditor verifikasi on-chain supply = reserve
	//   - Reconciliation: jumlah USDT on-chain = USD yang masuk ke bank
	//   - Regulatory: regulator cek Tether tidak mint melebihi reserve
	// =====================================================================
	balanceResp, err := t.tapd.ListBalances(
		ctx, &taprpc.ListBalancesRequest{
			GroupBy: &taprpc.ListBalancesRequest_AssetId{
				AssetId: true,
			},
		},
	)
	require.NoError(t.t, err)

	assetIDHex := hex.EncodeToString(mintedAsset.AssetGenesis.AssetId)
	assetBalance, ok := balanceResp.AssetBalances[assetIDHex]
	require.True(t.t, ok, "balance for USDT not found")
	require.Equal(t.t, uint64(100000000), assetBalance.Balance)

	// =====================================================================
	// ASSERTION 10: Batch dalam state FINALIZED
	// =====================================================================
	// Bisnis: State FINALIZED berarti transaksi Bitcoin sudah dikonfirmasi
	// on-chain dan semua proof telah di-generate. USDT siap untuk
	// didistribusikan ke exchange. State lain (PENDING, BROADCAST) berarti
	// proses belum selesai dan USDT belum bisa ditransfer.
	//
	// Catatan: MintAssetsConfirmBatch sudah memverifikasi ini secara
	// internal via WaitForBatchState, tapi kita verifikasi ulang secara
	// eksplisit melalui ListBatches untuk memastikan state persisten.
	// =====================================================================
	batchResp, err := t.tapd.ListBatches(
		ctx, &mintrpc.ListBatchRequest{},
	)
	require.NoError(t.t, err)
	require.NotEmpty(t.t, batchResp.Batches)

	// Cari batch yang mengandung USDT.
	var foundBatch *mintrpc.VerboseBatch
	for _, batch := range batchResp.Batches {
		for _, batchAsset := range batch.Batch.Assets {
			if batchAsset.Name == "usdt" {
				foundBatch = batch
				break
			}
		}
		if foundBatch != nil {
			break
		}
	}
	require.NotNil(t.t, foundBatch, "batch containing USDT not found")
	require.Equal(
		t.t, mintrpc.BatchState_BATCH_STATE_FINALIZED,
		foundBatch.Batch.State,
	)
	require.NotEmpty(t.t, foundBatch.Batch.BatchTxid)
}
