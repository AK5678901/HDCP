#define __STDC_FORMAT_MACROS /* Get the PRI* macros */

#include <stdio.h>
#include <stdlib.h>
#include <chrono>
#include <stdint.h>
#include <string.h>
#ifdef _WIN32
#include <windows.h>
#endif
#include "bitslice.h"
#include "hdcp_cipher.h"
#include "master_secret.h"


/* Print test vectors (See Tables A-3 and A-4 of HDCP Specification) */
int print_test_vectors(void)
{
  static bsvec_t Km[8] = {
    UINT64_C(0x5309c7d22fcecc), UINT64_C(0xf6aee46089c923), UINT64_C(0x4afe34dbec1205), UINT64_C(0xa423d78b8676a7),
    UINT64_C(0x5309c7d22fcecc), UINT64_C(0xf6aee46089c923), UINT64_C(0x4afe34dbec1205), UINT64_C(0xa423d78b8676a7) 
  };
  static bsvec_t REPEATER[8] = { 
    0, 0, 0, 0, 
    1, 1, 1, 1 
  };
  static bsvec_t An[8] = {
    UINT64_C(0x34271c130c070403), UINT64_C(0x445e62a53ad10fe5), UINT64_C(0x83bec2bb01c66e07), UINT64_C(0x0351f7175406a74d),
    UINT64_C(0x34271c130c070403), UINT64_C(0x445e62a53ad10fe5), UINT64_C(0x83bec2bb01c66e07), UINT64_C(0x0351f7175406a74d) 
  };

  static uint64_t Ks_true[8] = {
    UINT64_C(0x54294b7c040e35), UINT64_C(0x4e60d941d0e8b1), UINT64_C(0x2c9bef71df792e), UINT64_C(0x1963deb799ee82), 
    UINT64_C(0xbc607b21d48e97), UINT64_C(0xb7894f1754caaa), UINT64_C(0xfe3717c12f3bb1), UINT64_C(0xaac4147081a2d0)
  };

  static uint64_t R0_true[8] = {
    0x8ae0, 0xfb65, 0x3435, 0x4fd5,
    0x6485, 0x3f68, 0xdd9b, 0x7930
  };

  static uint64_t M0_true[8] = {
    UINT64_C(0xa02bc815e73d001c), UINT64_C(0xe7d28b9b2f46c49d), UINT64_C(0x8e1e91f6d8ae4c25), UINT64_C(0xd05d8c26378a126e),
    UINT64_C(0x372d3dce38bbe78f), UINT64_C(0x43d609c682c956e1), UINT64_C(0x536dee1e44a58bf4), UINT64_C(0x38b57ad3cdd1b266)
  };

  static uint64_t K1_true[8] = {
    UINT64_C(0xd692b7ee1d40e8), UINT64_C(0xe46f51311a959a), UINT64_C(0xf3e27849d067c1), UINT64_C(0x65f793e160ec27),
    UINT64_C(0x98b281e1876a9a), UINT64_C(0xffbfea4bc7fd2c), UINT64_C(0xa1ec276b2ddaf0), UINT64_C(0x0f0b83888e3209)
  };

  static uint64_t M1_true[8] = {
    UINT64_C(0x1dbf44e50f523e56), UINT64_C(0x445b5c6eebf657ff), UINT64_C(0x23d89127a5ee6c26), UINT64_C(0x68be984885aafef7),
    UINT64_C(0x016f9561e001f80d), UINT64_C(0x2a067368042fa1aa), UINT64_C(0xb365f8813c45db0b), UINT64_C(0x06471e358f601ce4)
  };

  static uint32_t outputs_true[8][2][8] = {
    { { 0x59c03e, 0x9ee5fe, 0x9af919, 0x5b5d6c, 0x55dcde, 0xe58763, 0xbefcc7, 0xa1b565 },
      { 0x126b14, 0x064a73, 0xf8bb15, 0xcce621, 0x879578, 0xd203f7, 0x628144, 0x80d875 } },
    
    { { 0x56bf8a, 0x2c2603, 0x8843dc, 0x1ddbbd, 0xe63213, 0x363424, 0x48828f, 0x99b9db },
      { 0x9cac7b, 0x4011d0, 0xaa3ce6, 0xe6e9ac, 0x7ad52e, 0x941f35, 0xa78564, 0xf74516 } },

    { { 0x1107d2, 0xb18f7f, 0x3cfb8c, 0xa3970c, 0x38943e, 0xac84da, 0xb8a473, 0x2fc5c0 },
      { 0x6c64c7, 0xba058d, 0x6217ff, 0xf1e5df, 0xc2e692, 0x47a494, 0x59b7a1, 0x9d96ea } },

    { { 0xb82c9c, 0x9b34e3, 0x1cfad7, 0x00a008, 0xcec3f4, 0xf43627, 0xb636f7, 0x24bd8b },
      { 0x739f2e, 0xf61e16, 0xe28c59, 0xd98a86, 0xc5eb96, 0xc0b3ce, 0xeb26f3, 0xf49ee1 } },
    
    { { 0x334e55, 0xd2374e, 0x0e22f5, 0xc1318f, 0xdca1a7, 0x27e7c3, 0x563ec9, 0x10dc2f },
      { 0x730322, 0x690136, 0x3d2753, 0xfe4150, 0xa8188d, 0x1a0291, 0x8c29ce, 0x89cdbf } },

    { { 0xbc9ca4, 0x4319df, 0xb1e012, 0x27d05a, 0xd8aa3d, 0x3f2a64, 0x2e000a, 0xf24763 },
      { 0xe497f1, 0xdf150e, 0x2f447b, 0x0c9bae, 0x93dbda, 0xa7f901, 0x1a399a, 0x4b5400 } },

    { { 0x4ac7d3, 0x30a7ec, 0x2d6e36, 0xe175b6, 0x94fffb, 0x11aac1, 0x5c7166, 0xbe336f },
      { 0x0ba7ec, 0x4f101e, 0xfe1616, 0x52e635, 0xdb8db7, 0x18f0d9, 0xf59a63, 0xd4acaa } },

    { { 0xc2c884, 0x2f7c68, 0x900be5, 0x9ede54, 0x78cd8c, 0x38a5b8, 0x32ff1e, 0xe4d90c },
      { 0x620f61, 0x337352, 0xcd96fd, 0x53ead5, 0x33a931, 0xcc3486, 0x6ee0bb, 0xd2fc4b } }
  };

  int i, j, r, all_passed = 1;

  
  for (i = 0; i < 8; i++) {
      BS_HDCPCipherState hs;
      bsvec_t Ks, R0, M0, K1, R1, M1;
      uint32_t outputs[2][8][1];
      int passed;

      HDCPBlockCipher(1, &Km[i], &REPEATER[i], &An[i], &hs, &Ks, &R0, &M0);
      HDCPInitializeMultiFrameState(1, Ks, REPEATER[i], M0, &hs, &K1, &R1, &M1);
      HDCPFrameStream(1, 2, 8, &hs, &outputs[0][0][0]);

  #define PASSED(x) (x == x ## _true[i])
      passed = PASSED(Ks) && PASSED(M0) && PASSED(R0) && PASSED(K1) && PASSED(M1);

      // テストケースごとのヘッダーと鍵・初期値の表示
      printf("========================================\n");
      printf(" Test Case #%d (Repeater: %" PRIu64 ")\n", i, REPEATER[i]);
      printf("========================================\n");
      printf("  [Keys & Init Values]\n");
      printf("  Ks : 0x%014" PRIx64 " %s\n", Ks, PASSED(Ks) ? "[PASS]" : "[FAIL !]");
      printf("  M0 : 0x%016" PRIx64 " %s\n", M0, PASSED(M0) ? "[PASS]" : "[FAIL !]");
      printf("  R0 : 0x%04" PRIx64 "     %s\n", R0, PASSED(R0) ? "[PASS]" : "[FAIL !]");
      printf("  K1 : 0x%014" PRIx64 " %s\n", K1, PASSED(K1) ? "[PASS]" : "[FAIL !]");
      printf("  M1 : 0x%016" PRIx64 " %s\n", M1, PASSED(M1) ? "[PASS]" : "[FAIL !]");
  #undef PASSED

      all_passed &= passed;

  #define PASSED(i,r,j) (outputs[r][j][0] == outputs_true[i][r][j])
      
      // ストリーム暗号出力の表示
      printf("\n  [Stream Cipher Outputs]\n");
      for (r = 0; r < 2; r++) {
          int frame_passed = 1;
          printf("  Frame %d: ", r);
          for (j = 0; j < 8; j++) {
              frame_passed &= PASSED(i,r,j);
              printf("0x%06x%s ", outputs[r][j][0], PASSED(i,r,j) ? "" : "(!)");
          }
          all_passed &= frame_passed;
          printf(" %s\n", frame_passed ? "[PASS]" : "[FAIL !]");
      }
      printf("\n");
  }


  if (all_passed)
    printf("************* ALL TESTS PASSED ****************\n");
  else
    printf("!!!!!!!!!!!!! SOME TESTS FAILED !!!!!!!!!!!!!!!\n");

  return all_passed ? 0 : 1;
}

using Clock = std::chrono::steady_clock;
static int64_t elapsed(Clock::time_point start, Clock::time_point end)
{
  return std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
}

int measure_hdcp_block_speed(void)
{
  bsvec_t Km[BSBITS], REPEATER[BSBITS], An[BSBITS], Ks[BSBITS], R0[BSBITS], M0[BSBITS];
  BS_HDCPCipherState hs;
  Clock::time_point tv1, tv2;
  int64_t count;

  count = 0;
  tv1 = Clock::now();
  do {
    int i;
    for (i = 0; i < 100; i++)
      HDCPBlockCipher(BSBITS, Km, REPEATER, An, &hs, Ks, R0, M0);
    count += 100;
    tv2 = Clock::now();
  } while (elapsed(tv1, tv2) < 3000000);
  
  return BSBITS*1000000 * count/elapsed(tv1, tv2);
}

int measure_hdcp_stream_speed(void)
{
  bsvec_t Km = UINT64_C(0x1234567890abcd), REPEATER = 0, 
    An = UINT64_C(0xfedcba0987654321), Ks, R0, M0, Ki[BSBITS], Ri[BSBITS], Mi[BSBITS];
  static uint32_t outputs[480][640][BSBITS];
  BS_HDCPCipherState hs;
  Clock::time_point tv1, tv2;
  int64_t count;

  HDCPAuthentication(Km, REPEATER, An, &Ks, &R0, &M0);

  count = 0;
  Mi[BSBITS-1] = M0;
  tv1 = Clock::now();
  do {
    HDCPInitializeMultiFrameState(BSBITS, Ks, 0, Mi[BSBITS-1], &hs, Ki, Ri, Mi);
    HDCPFrameStream(BSBITS, 480, 640, &hs, &outputs[0][0][0]);
    
    count += BSBITS;
    tv2 = Clock::now();
  } while (elapsed(tv1, tv2) < 3000000);
  
  return 1000000 * count/ elapsed(tv1, tv2);
}

#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>



/**
 * 厳密なHDCP（Blomスキーム）仕様に沿ったカスタムセッション実行関数
 * master_secret は 40 x 40 の2次元対称行列を想定
 */
void run_custom_hdcp_session(uint64_t An, uint64_t Aksv, uint64_t Bksv, const uint64_t master_secret[40][40], uint64_t repeater) {
    BS_HDCPCipherState hs;
    bsvec_t Ks, R0, M0, K1, R1, M1;
    uint32_t outputs[2][8][1];
    uint64_t Km = 0;
    int a_count = 0;
    int b_count = 0;
    int i, j, r;

    // Aksv のバリデーション (40ビット中、正確に20個のビットが1であるか確認)
    for (i = 0; i < 40; i++) {
        if ((Aksv >> i) & 1) {
            a_count++;
        }
    }

    // Bksv のバリデーション (40ビット中、正確に20個のビットが1であるか確認)
    for (i = 0; i < 40; i++) {
        if ((Bksv >> i) & 1) {
            b_count++;
        }
    }

    printf("========================================\n");
    printf(" Custom HDCP Session Execution Results  \n");
    printf("========================================\n");
    
    // 入力パラメーターの明示的な出力
    printf("[Input Parameters]\n");
    printf("  An       : 0x%016" PRIx64 "\n", An);
    printf("  Aksv     : 0x%010" PRIx64 " (1-bits: %d/20)\n", Aksv, a_count);
    printf("  Bksv     : 0x%010" PRIx64 " (1-bits: %d/20)\n", Bksv, b_count);
    printf("  Repeater : %" PRIu64 " (%s)\n", repeater, repeater ? "True (リピータ)" : "False (通常機器)");
    printf("\n");

    if (a_count != 20 || b_count != 20) {
        printf("[X] エラー: Aksv または Bksv の有効性検証に失敗しました (1のビット数が20ではありません)。\n");
        printf("========================================\n\n");
        return;
    }

    uint64_t K_dev_A[40] = {0}; // A側（Tx）の秘密鍵配列
    uint64_t K_dev_B[40] = {0}; // B側（Rx）の秘密鍵配列
    uint64_t Km_A = 0;
    uint64_t Km_B = 0;

    // 1. A側の秘密鍵配列を生成 (マスター行列の「行」を Aksv のビット位置に従って足し合わせる)
    for (int i = 0; i < 40; i++) {
        if ((Aksv >> i) & 1) {
            for (int k = 0; k < 40; k++) {
                K_dev_A[k] = (K_dev_A[k] + master_secret[i][k]) & 0xFFFFFFFFFFFFFFULL;
            }
        }
    }

    // 2. B側の秘密鍵配列を生成 (転置マスター行列の「行」= 元行列の「列」を Bksv のビット位置に従って足し合わせる)
    for (int j = 0; j < 40; j++) {
        if ((Bksv >> j) & 1) {
            for (int k = 0; k < 40; k++) {
                K_dev_B[k] = (K_dev_B[k] + master_secret[k][j]) & 0xFFFFFFFFFFFFFFULL;
            }
        }
    }

    // 3. 双方の視点から Km が完全に一致することの確認
    
    // A側（Tx）視点: 相手の Bksv のビット位置に対応する、自分の秘密鍵 (K_dev_A) を加算
    for (int i = 0; i < 40; i++) {
        if ((Bksv >> i) & 1) {
            Km_A = (Km_A + K_dev_A[i]) & 0xFFFFFFFFFFFFFFULL;
        }
    }

    // B側（Rx）視点: 相手の Aksv のビット位置に対応する、自分の秘密鍵 (K_dev_B) を加算
    for (int j = 0; j < 40; j++) {
        if ((Aksv >> j) & 1) {
            Km_B = (Km_B + K_dev_B[j]) & 0xFFFFFFFFFFFFFFULL;
        }
    }

    // --- 厳密なBlom鍵共有スキームによる Km 計算 ---
    for (i = 0; i < 40; i++) {
        if ((Aksv >> i) & 1) {
            for (j = 0; j < 40; j++) {
                if ((Bksv >> j) & 1) {
                    Km = (Km + master_secret[i][j]) & 0xFFFFFFFFFFFFFFULL;
                }
            }
        }
    }

    // コア暗号処理関数の呼び出し
    HDCPBlockCipher(1, &Km, &repeater, &An, &hs, &Ks, &R0, &M0);
    HDCPInitializeMultiFrameState(1, Ks, repeater, M0, &hs, &K1, &R1, &M1);
    HDCPFrameStream(1, 2, 8, &hs, &outputs[0][0][0]);

    // 計算結果の出力
    printf("[Derived Keys & Init Values]\n");
    printf("  Km (直接計算)   : 0x%014" PRIx64 "\n", Km);
    printf("  Km_A (A側視点)  : 0x%014" PRIx64 " %s\n", Km_A, (Km_A == Km) ? "(一致)" : "(不一致!)");
    printf("  Km_B (B側視点)  : 0x%014" PRIx64 " %s\n", Km_B, (Km_B == Km) ? "(一致)" : "(不一致!)");
    
    printf("  Ks (セッション) : 0x%014" PRIx64 "\n", Ks);
    printf("  M0 (初期秘密値) : 0x%016" PRIx64 "\n", M0);
    printf("  R0 (初期検証値) : 0x%04" PRIx64 "\n", R0);
    printf("  K1 (次フレーム) : 0x%014" PRIx64 "\n", K1);
    printf("  M1 (次フレーム) : 0x%016" PRIx64 "\n", M1);

    printf("\n[Stream Cipher Outputs]\n");
    for (r = 0; r < 2; r++) {
        printf("  Frame %d: ", r);
        for (j = 0; j < 8; j++) {
            printf("0x%06x ", outputs[r][j][0]);
        }
        printf("\n");
    }

    // デバイス秘密鍵（K_dev_A および K_dev_B）を最後に表示
    printf("\n[Full Device Secret Keys (K_dev_A & K_dev_B)]\n");
    for (int k = 0; k < 40; k++) {
        if (k % 4 == 0) printf("  ");
        printf("K_A[%2d]:0x%014" PRIx64 " ", k, K_dev_A[k]);
        if (k % 4 == 3) printf("\n");
    }
    printf("\n");
    for (int k = 0; k < 40; k++) {
        if (k % 4 == 0) printf("  ");
        printf("K_B[%2d]:0x%014" PRIx64 " ", k, K_dev_B[k]);
        if (k % 4 == 3) printf("\n");
    }
    printf("========================================\n\n");
}

int main(int argc, char *argv[])
{
#ifdef _WIN32
  SetConsoleOutputCP(CP_UTF8);
#endif

  if (argc == 2 && strcmp(argv[1], "-t") == 0) {
    return print_test_vectors();
  }

  if (argc == 2 && strcmp(argv[1], "-k") == 0) {
    // 不具合ケーブル
    const uint64_t test_An   = 0x3232e6f7b382ca12ULL;
    const uint64_t test_Aksv = 0x7269c30af9ULL; // 20個の1を持つKSV
    const uint64_t test_Bksv = 0x3a5f4bc05aULL; // 20個の1を持つKSV
    const uint64_t test_rep  = 1;                // リピータ

    run_custom_hdcp_session(test_An, test_Aksv, test_Bksv, my_master_secret, test_rep);

    return 0;
  }

  else if (argc == 2 && strcmp(argv[1], "-S") == 0) {
    //printf("BlockCiphers/second: %d\n", measure_hdcp_block_speed());
    printf("640x480 Frames/second: %d\n", measure_hdcp_stream_speed());
  }

  else {
    printf(
	   "hdcp -t\n"
	   "  Print HDCP test vectors\n\n"
	   "hdcp -S\n"
	   "  Run hdcp speed trials\n\n"
	   );
  }

  return 0;
}
