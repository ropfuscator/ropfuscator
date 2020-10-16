#include <stdint.h>
#include <stdlib.h>
int64_t check_0(int64_t cur) {
  if (0 == cur) exit(1);
  cur = cur + 26; // 32 + 26 = 58
  cur = cur + 23; // 58 + 23 = 81
  cur = cur - 33; // 81 - 33 = 48
  cur = cur + 29; // 48 + 29 = 77
  cur = cur - 3; // 77 - 3 = 74
  cur = cur - 23; // 74 - 23 = 51
  cur = cur + 20; // 51 + 20 = 71
  cur = cur - 34; // 71 - 34 = 37
  cur = cur - 30; // 37 - 30 = 7
  cur = cur - 31; // 7 - 31 = -24
  cur = cur - 17; // -24 - 17 = -41
  cur = cur + 8; // -41 + 8 = -33
  cur = cur - 10; // -33 - 10 = -43
  cur = cur - 22; // -43 - 22 = -65
  cur = cur + 10; // -65 + 10 = -55
  cur = cur + 29; // -55 + 29 = -26
  cur = cur + 4; // -26 + 4 = -22
  cur = cur + 19; // -22 + 19 = -3
  cur = cur - 7; // -3 - 7 = -10
  cur = cur - 17; // -10 - 17 = -27
  cur = cur + 5; // -27 + 5 = -22
  cur = cur + 4; // -22 + 4 = -18
  cur = cur - 7; // -18 - 7 = -25
  cur = cur + 10; // -25 + 10 = -15
  cur = cur + 5; // -15 + 5 = -10
  cur = cur - 21; // -10 - 21 = -31
  cur = cur - 21; // -31 - 21 = -52
  cur = cur + 27; // -52 + 27 = -25
  cur = cur + 23; // -25 + 23 = -2
  cur = cur + 18; // -2 + 18 = 16
  cur = cur + 20; // 16 + 20 = 36
  cur = cur - 30; // 36 - 30 = 6
  if (6 != cur) exit(1);
  return cur;
}

int64_t check_1(int64_t cur) {
  if (0 == cur) exit(2);
  cur = cur + 18; // 109 + 18 = 127
  cur = cur - 17; // 127 - 17 = 110
  cur = cur + 21; // 110 + 21 = 131
  cur = cur + 20; // 131 + 20 = 151
  cur = cur + 19; // 151 + 19 = 170
  cur = cur - 8; // 170 - 8 = 162
  cur = cur + 21; // 162 + 21 = 183
  cur = cur + 14; // 183 + 14 = 197
  cur = cur - 13; // 197 - 13 = 184
  cur = cur + 24; // 184 + 24 = 208
  cur = cur + 29; // 208 + 29 = 237
  cur = cur - 21; // 237 - 21 = 216
  cur = cur - 32; // 216 - 32 = 184
  cur = cur - 6; // 184 - 6 = 178
  cur = cur + 6; // 178 + 6 = 184
  cur = cur + 24; // 184 + 24 = 208
  cur = cur + 16; // 208 + 16 = 224
  cur = cur + 24; // 224 + 24 = 248
  cur = cur + 31; // 248 + 31 = 279
  cur = cur - 8; // 279 - 8 = 271
  cur = cur + 5; // 271 + 5 = 276
  cur = cur + 5; // 276 + 5 = 281
  cur = cur + 21; // 281 + 21 = 302
  cur = cur - 13; // 302 - 13 = 289
  cur = cur - 20; // 289 - 20 = 269
  cur = cur + 6; // 269 + 6 = 275
  cur = cur - 20; // 275 - 20 = 255
  cur = cur - 23; // 255 - 23 = 232
  cur = cur - 24; // 232 - 24 = 208
  cur = cur - 12; // 208 - 12 = 196
  cur = cur - 13; // 196 - 13 = 183
  cur = cur - 14; // 183 - 14 = 169
  if (169 != cur) exit(2);
  return cur;
}

int64_t check_2(int64_t cur) {
  if (0 == cur) exit(3);
  cur = cur + 33; // 121 + 33 = 154
  cur = cur - 26; // 154 - 26 = 128
  cur = cur + 30; // 128 + 30 = 158
  cur = cur - 3; // 158 - 3 = 155
  cur = cur - 31; // 155 - 31 = 124
  cur = cur - 7; // 124 - 7 = 117
  cur = cur + 29; // 117 + 29 = 146
  cur = cur + 4; // 146 + 4 = 150
  cur = cur + 17; // 150 + 17 = 167
  cur = cur - 13; // 167 - 13 = 154
  cur = cur + 8; // 154 + 8 = 162
  cur = cur + 4; // 162 + 4 = 166
  cur = cur + 12; // 166 + 12 = 178
  cur = cur - 20; // 178 - 20 = 158
  cur = cur - 19; // 158 - 19 = 139
  cur = cur + 5; // 139 + 5 = 144
  cur = cur - 29; // 144 - 29 = 115
  cur = cur - 33; // 115 - 33 = 82
  cur = cur - 14; // 82 - 14 = 68
  cur = cur + 8; // 68 + 8 = 76
  cur = cur - 32; // 76 - 32 = 44
  cur = cur - 13; // 44 - 13 = 31
  cur = cur + 26; // 31 + 26 = 57
  cur = cur - 14; // 57 - 14 = 43
  cur = cur - 16; // 43 - 16 = 27
  cur = cur + 29; // 27 + 29 = 56
  cur = cur - 3; // 56 - 3 = 53
  cur = cur + 24; // 53 + 24 = 77
  cur = cur + 32; // 77 + 32 = 109
  cur = cur + 21; // 109 + 21 = 130
  cur = cur - 4; // 130 - 4 = 126
  cur = cur - 5; // 126 - 5 = 121
  if (121 != cur) exit(3);
  return cur;
}

int64_t check_3(int64_t cur) {
  if (0 == cur) exit(4);
  cur = cur + 20; // 32 + 20 = 52
  cur = cur + 29; // 52 + 29 = 81
  cur = cur + 15; // 81 + 15 = 96
  cur = cur - 8; // 96 - 8 = 88
  cur = cur + 27; // 88 + 27 = 115
  cur = cur + 12; // 115 + 12 = 127
  cur = cur + 20; // 127 + 20 = 147
  cur = cur + 16; // 147 + 16 = 163
  cur = cur + 5; // 163 + 5 = 168
  cur = cur + 32; // 168 + 32 = 200
  cur = cur + 26; // 200 + 26 = 226
  cur = cur - 31; // 226 - 31 = 195
  cur = cur - 7; // 195 - 7 = 188
  cur = cur + 14; // 188 + 14 = 202
  cur = cur - 19; // 202 - 19 = 183
  cur = cur - 5; // 183 - 5 = 178
  cur = cur - 12; // 178 - 12 = 166
  cur = cur + 27; // 166 + 27 = 193
  cur = cur + 31; // 193 + 31 = 224
  cur = cur + 25; // 224 + 25 = 249
  cur = cur + 10; // 249 + 10 = 259
  cur = cur + 3; // 259 + 3 = 262
  cur = cur - 8; // 262 - 8 = 254
  cur = cur + 25; // 254 + 25 = 279
  cur = cur - 34; // 279 - 34 = 245
  cur = cur + 17; // 245 + 17 = 262
  cur = cur + 23; // 262 + 23 = 285
  cur = cur + 13; // 285 + 13 = 298
  cur = cur + 3; // 298 + 3 = 301
  cur = cur - 11; // 301 - 11 = 290
  cur = cur - 9; // 290 - 9 = 281
  cur = cur - 19; // 281 - 19 = 262
  if (262 != cur) exit(4);
  return cur;
}

int64_t check_4(int64_t cur) {
  if (0 == cur) exit(5);
  cur = cur - 18; // 116 - 18 = 98
  cur = cur + 34; // 98 + 34 = 132
  cur = cur - 7; // 132 - 7 = 125
  cur = cur + 16; // 125 + 16 = 141
  cur = cur + 5; // 141 + 5 = 146
  cur = cur + 20; // 146 + 20 = 166
  cur = cur - 7; // 166 - 7 = 159
  cur = cur + 32; // 159 + 32 = 191
  cur = cur - 15; // 191 - 15 = 176
  cur = cur - 34; // 176 - 34 = 142
  cur = cur - 7; // 142 - 7 = 135
  cur = cur + 8; // 135 + 8 = 143
  cur = cur - 31; // 143 - 31 = 112
  cur = cur - 13; // 112 - 13 = 99
  cur = cur + 15; // 99 + 15 = 114
  cur = cur + 5; // 114 + 5 = 119
  cur = cur - 17; // 119 - 17 = 102
  cur = cur + 18; // 102 + 18 = 120
  cur = cur + 9; // 120 + 9 = 129
  cur = cur - 27; // 129 - 27 = 102
  cur = cur - 13; // 102 - 13 = 89
  cur = cur - 14; // 89 - 14 = 75
  cur = cur - 4; // 75 - 4 = 71
  cur = cur + 26; // 71 + 26 = 97
  cur = cur + 16; // 97 + 16 = 113
  cur = cur - 15; // 113 - 15 = 98
  cur = cur - 13; // 98 - 13 = 85
  cur = cur - 26; // 85 - 26 = 59
  cur = cur - 33; // 59 - 33 = 26
  cur = cur + 34; // 26 + 34 = 60
  cur = cur - 4; // 60 - 4 = 56
  cur = cur + 20; // 56 + 20 = 76
  if (76 != cur) exit(5);
  return cur;
}

int64_t check_5(int64_t cur) {
  if (0 == cur) exit(6);
  cur = cur - 14; // 111 - 14 = 97
  cur = cur + 28; // 97 + 28 = 125
  cur = cur - 33; // 125 - 33 = 92
  cur = cur + 30; // 92 + 30 = 122
  cur = cur + 27; // 122 + 27 = 149
  cur = cur + 23; // 149 + 23 = 172
  cur = cur + 17; // 172 + 17 = 189
  cur = cur - 14; // 189 - 14 = 175
  cur = cur + 28; // 175 + 28 = 203
  cur = cur - 34; // 203 - 34 = 169
  cur = cur - 30; // 169 - 30 = 139
  cur = cur - 15; // 139 - 15 = 124
  cur = cur + 13; // 124 + 13 = 137
  cur = cur - 26; // 137 - 26 = 111
  cur = cur - 20; // 111 - 20 = 91
  cur = cur + 10; // 91 + 10 = 101
  cur = cur - 10; // 101 - 10 = 91
  cur = cur - 21; // 91 - 21 = 70
  cur = cur - 16; // 70 - 16 = 54
  cur = cur + 5; // 54 + 5 = 59
  cur = cur - 9; // 59 - 9 = 50
  cur = cur - 14; // 50 - 14 = 36
  cur = cur - 30; // 36 - 30 = 6
  cur = cur + 32; // 6 + 32 = 38
  cur = cur - 7; // 38 - 7 = 31
  cur = cur - 23; // 31 - 23 = 8
  cur = cur - 14; // 8 - 14 = -6
  cur = cur - 34; // -6 - 34 = -40
  cur = cur - 21; // -40 - 21 = -61
  cur = cur + 16; // -61 + 16 = -45
  cur = cur + 5; // -45 + 5 = -40
  cur = cur + 25; // -40 + 25 = -15
  if (-15 != cur) exit(6);
  return cur;
}

int64_t check_6(int64_t cur) {
  if (0 == cur) exit(7);
  cur = cur - 33; // 101 - 33 = 68
  cur = cur + 26; // 68 + 26 = 94
  cur = cur - 17; // 94 - 17 = 77
  cur = cur + 31; // 77 + 31 = 108
  cur = cur + 32; // 108 + 32 = 140
  cur = cur + 12; // 140 + 12 = 152
  cur = cur + 30; // 152 + 30 = 182
  cur = cur - 6; // 182 - 6 = 176
  cur = cur - 3; // 176 - 3 = 173
  cur = cur + 4; // 173 + 4 = 177
  cur = cur - 21; // 177 - 21 = 156
  cur = cur - 33; // 156 - 33 = 123
  cur = cur + 21; // 123 + 21 = 144
  cur = cur + 11; // 144 + 11 = 155
  cur = cur - 21; // 155 - 21 = 134
  cur = cur + 30; // 134 + 30 = 164
  cur = cur - 32; // 164 - 32 = 132
  cur = cur - 32; // 132 - 32 = 100
  cur = cur + 30; // 100 + 30 = 130
  cur = cur - 12; // 130 - 12 = 118
  cur = cur - 31; // 118 - 31 = 87
  cur = cur + 9; // 87 + 9 = 96
  cur = cur - 31; // 96 - 31 = 65
  cur = cur - 13; // 65 - 13 = 52
  cur = cur + 24; // 52 + 24 = 76
  cur = cur - 17; // 76 - 17 = 59
  cur = cur - 16; // 59 - 16 = 43
  cur = cur + 21; // 43 + 21 = 64
  cur = cur - 21; // 64 - 21 = 43
  cur = cur + 18; // 43 + 18 = 61
  cur = cur + 23; // 61 + 23 = 84
  cur = cur - 20; // 84 - 20 = 64
  if (64 != cur) exit(7);
  return cur;
}

int64_t check_7(int64_t cur) {
  if (0 == cur) exit(8);
  cur = cur + 12; // 32 + 12 = 44
  cur = cur + 27; // 44 + 27 = 71
  cur = cur + 29; // 71 + 29 = 100
  cur = cur + 18; // 100 + 18 = 118
  cur = cur - 24; // 118 - 24 = 94
  cur = cur - 3; // 94 - 3 = 91
  cur = cur - 10; // 91 - 10 = 81
  cur = cur + 18; // 81 + 18 = 99
  cur = cur + 3; // 99 + 3 = 102
  cur = cur - 33; // 102 - 33 = 69
  cur = cur + 5; // 69 + 5 = 74
  cur = cur - 22; // 74 - 22 = 52
  cur = cur - 12; // 52 - 12 = 40
  cur = cur - 21; // 40 - 21 = 19
  cur = cur - 15; // 19 - 15 = 4
  cur = cur + 5; // 4 + 5 = 9
  cur = cur + 13; // 9 + 13 = 22
  cur = cur - 8; // 22 - 8 = 14
  cur = cur + 3; // 14 + 3 = 17
  cur = cur + 12; // 17 + 12 = 29
  cur = cur + 29; // 29 + 29 = 58
  cur = cur - 28; // 58 - 28 = 30
  cur = cur + 29; // 30 + 29 = 59
  cur = cur - 15; // 59 - 15 = 44
  cur = cur - 15; // 44 - 15 = 29
  cur = cur - 12; // 29 - 12 = 17
  cur = cur - 22; // 17 - 22 = -5
  cur = cur - 16; // -5 - 16 = -21
  cur = cur + 5; // -21 + 5 = -16
  cur = cur - 9; // -16 - 9 = -25
  cur = cur - 17; // -25 - 17 = -42
  cur = cur + 8; // -42 + 8 = -34
  if (-34 != cur) exit(8);
  return cur;
}

int64_t check_8(int64_t cur) {
  if (0 == cur) exit(9);
  cur = cur - 18; // 105 - 18 = 87
  cur = cur + 12; // 87 + 12 = 99
  cur = cur - 24; // 99 - 24 = 75
  cur = cur + 5; // 75 + 5 = 80
  cur = cur + 9; // 80 + 9 = 89
  cur = cur - 31; // 89 - 31 = 58
  cur = cur - 22; // 58 - 22 = 36
  cur = cur + 28; // 36 + 28 = 64
  cur = cur - 32; // 64 - 32 = 32
  cur = cur + 14; // 32 + 14 = 46
  cur = cur - 19; // 46 - 19 = 27
  cur = cur - 25; // 27 - 25 = 2
  cur = cur - 5; // 2 - 5 = -3
  cur = cur + 8; // -3 + 8 = 5
  cur = cur - 13; // 5 - 13 = -8
  cur = cur - 16; // -8 - 16 = -24
  cur = cur - 34; // -24 - 34 = -58
  cur = cur - 21; // -58 - 21 = -79
  cur = cur + 18; // -79 + 18 = -61
  cur = cur - 7; // -61 - 7 = -68
  cur = cur + 18; // -68 + 18 = -50
  cur = cur + 25; // -50 + 25 = -25
  cur = cur - 33; // -25 - 33 = -58
  cur = cur - 14; // -58 - 14 = -72
  cur = cur - 21; // -72 - 21 = -93
  cur = cur + 31; // -93 + 31 = -62
  cur = cur - 29; // -62 - 29 = -91
  cur = cur + 9; // -91 + 9 = -82
  cur = cur + 11; // -82 + 11 = -71
  cur = cur + 13; // -71 + 13 = -58
  cur = cur - 13; // -58 - 13 = -71
  cur = cur + 31; // -71 + 31 = -40
  if (-40 != cur) exit(9);
  return cur;
}

int64_t check_9(int64_t cur) {
  if (0 == cur) exit(10);
  cur = cur + 4; // 110 + 4 = 114
  cur = cur + 24; // 114 + 24 = 138
  cur = cur - 7; // 138 - 7 = 131
  cur = cur + 11; // 131 + 11 = 142
  cur = cur + 3; // 142 + 3 = 145
  cur = cur + 27; // 145 + 27 = 172
  cur = cur - 12; // 172 - 12 = 160
  cur = cur + 9; // 160 + 9 = 169
  cur = cur + 25; // 169 + 25 = 194
  cur = cur + 31; // 194 + 31 = 225
  cur = cur + 9; // 225 + 9 = 234
  cur = cur - 24; // 234 - 24 = 210
  cur = cur - 11; // 210 - 11 = 199
  cur = cur - 32; // 199 - 32 = 167
  cur = cur - 22; // 167 - 22 = 145
  cur = cur + 17; // 145 + 17 = 162
  cur = cur + 32; // 162 + 32 = 194
  cur = cur - 24; // 194 - 24 = 170
  cur = cur - 23; // 170 - 23 = 147
  cur = cur - 6; // 147 - 6 = 141
  cur = cur - 4; // 141 - 4 = 137
  cur = cur + 4; // 137 + 4 = 141
  cur = cur - 33; // 141 - 33 = 108
  cur = cur - 18; // 108 - 18 = 90
  cur = cur - 12; // 90 - 12 = 78
  cur = cur + 4; // 78 + 4 = 82
  cur = cur + 15; // 82 + 15 = 97
  cur = cur + 27; // 97 + 27 = 124
  cur = cur - 5; // 124 - 5 = 119
  cur = cur - 4; // 119 - 4 = 115
  cur = cur + 20; // 115 + 20 = 135
  cur = cur + 20; // 135 + 20 = 155
  if (155 != cur) exit(10);
  return cur;
}

int64_t check_10(int64_t cur) {
  if (0 == cur) exit(11);
  cur = cur + 34; // 32 + 34 = 66
  cur = cur + 18; // 66 + 18 = 84
  cur = cur - 25; // 84 - 25 = 59
  cur = cur + 19; // 59 + 19 = 78
  cur = cur - 9; // 78 - 9 = 69
  cur = cur + 14; // 69 + 14 = 83
  cur = cur - 12; // 83 - 12 = 71
  cur = cur - 22; // 71 - 22 = 49
  cur = cur + 10; // 49 + 10 = 59
  cur = cur - 6; // 59 - 6 = 53
  cur = cur - 25; // 53 - 25 = 28
  cur = cur - 5; // 28 - 5 = 23
  cur = cur + 32; // 23 + 32 = 55
  cur = cur - 26; // 55 - 26 = 29
  cur = cur - 14; // 29 - 14 = 15
  cur = cur + 8; // 15 + 8 = 23
  cur = cur + 29; // 23 + 29 = 52
  cur = cur - 20; // 52 - 20 = 32
  cur = cur - 30; // 32 - 30 = 2
  cur = cur + 19; // 2 + 19 = 21
  cur = cur + 19; // 21 + 19 = 40
  cur = cur - 21; // 40 - 21 = 19
  cur = cur - 12; // 19 - 12 = 7
  cur = cur - 5; // 7 - 5 = 2
  cur = cur + 25; // 2 + 25 = 27
  cur = cur - 10; // 27 - 10 = 17
  cur = cur + 13; // 17 + 13 = 30
  cur = cur - 32; // 30 - 32 = -2
  cur = cur - 30; // -2 - 30 = -32
  cur = cur - 28; // -32 - 28 = -60
  cur = cur + 26; // -60 + 26 = -34
  cur = cur - 14; // -34 - 14 = -48
  if (-48 != cur) exit(11);
  return cur;
}

int64_t check_11(int64_t cur) {
  if (0 == cur) exit(12);
  cur = cur - 33; // 98 - 33 = 65
  cur = cur + 31; // 65 + 31 = 96
  cur = cur - 27; // 96 - 27 = 69
  cur = cur + 12; // 69 + 12 = 81
  cur = cur + 7; // 81 + 7 = 88
  cur = cur + 5; // 88 + 5 = 93
  cur = cur + 14; // 93 + 14 = 107
  cur = cur - 7; // 107 - 7 = 100
  cur = cur + 17; // 100 + 17 = 117
  cur = cur - 10; // 117 - 10 = 107
  cur = cur + 16; // 107 + 16 = 123
  cur = cur - 8; // 123 - 8 = 115
  cur = cur - 7; // 115 - 7 = 108
  cur = cur + 24; // 108 + 24 = 132
  cur = cur + 11; // 132 + 11 = 143
  cur = cur - 8; // 143 - 8 = 135
  cur = cur - 20; // 135 - 20 = 115
  cur = cur + 6; // 115 + 6 = 121
  cur = cur - 18; // 121 - 18 = 103
  cur = cur - 18; // 103 - 18 = 85
  cur = cur - 18; // 85 - 18 = 67
  cur = cur - 23; // 67 - 23 = 44
  cur = cur - 10; // 44 - 10 = 34
  cur = cur + 6; // 34 + 6 = 40
  cur = cur + 16; // 40 + 16 = 56
  cur = cur + 26; // 56 + 26 = 82
  cur = cur + 26; // 82 + 26 = 108
  cur = cur + 25; // 108 + 25 = 133
  cur = cur + 5; // 133 + 5 = 138
  cur = cur - 21; // 138 - 21 = 117
  cur = cur + 21; // 117 + 21 = 138
  cur = cur + 5; // 138 + 5 = 143
  if (143 != cur) exit(12);
  return cur;
}

int64_t check_12(int64_t cur) {
  if (0 == cur) exit(13);
  cur = cur - 29; // 101 - 29 = 72
  cur = cur + 29; // 72 + 29 = 101
  cur = cur + 10; // 101 + 10 = 111
  cur = cur - 31; // 111 - 31 = 80
  cur = cur + 23; // 80 + 23 = 103
  cur = cur - 34; // 103 - 34 = 69
  cur = cur - 4; // 69 - 4 = 65
  cur = cur - 14; // 65 - 14 = 51
  cur = cur - 29; // 51 - 29 = 22
  cur = cur + 27; // 22 + 27 = 49
  cur = cur - 6; // 49 - 6 = 43
  cur = cur - 8; // 43 - 8 = 35
  cur = cur + 14; // 35 + 14 = 49
  cur = cur + 3; // 49 + 3 = 52
  cur = cur - 16; // 52 - 16 = 36
  cur = cur - 27; // 36 - 27 = 9
  cur = cur - 7; // 9 - 7 = 2
  cur = cur + 7; // 2 + 7 = 9
  cur = cur - 6; // 9 - 6 = 3
  cur = cur - 5; // 3 - 5 = -2
  cur = cur - 15; // -2 - 15 = -17
  cur = cur - 19; // -17 - 19 = -36
  cur = cur + 34; // -36 + 34 = -2
  cur = cur - 23; // -2 - 23 = -25
  cur = cur - 19; // -25 - 19 = -44
  cur = cur + 22; // -44 + 22 = -22
  cur = cur - 33; // -22 - 33 = -55
  cur = cur + 6; // -55 + 6 = -49
  cur = cur - 22; // -49 - 22 = -71
  cur = cur - 25; // -71 - 25 = -96
  cur = cur - 15; // -96 - 15 = -111
  cur = cur - 17; // -111 - 17 = -128
  if (-128 != cur) exit(13);
  return cur;
}

int64_t check_13(int64_t cur) {
  if (0 == cur) exit(14);
  cur = cur - 16; // 102 - 16 = 86
  cur = cur - 30; // 86 - 30 = 56
  cur = cur - 7; // 56 - 7 = 49
  cur = cur - 10; // 49 - 10 = 39
  cur = cur - 6; // 39 - 6 = 33
  cur = cur + 30; // 33 + 30 = 63
  cur = cur - 17; // 63 - 17 = 46
  cur = cur - 27; // 46 - 27 = 19
  cur = cur - 25; // 19 - 25 = -6
  cur = cur + 5; // -6 + 5 = -1
  cur = cur - 26; // -1 - 26 = -27
  cur = cur - 17; // -27 - 17 = -44
  cur = cur - 6; // -44 - 6 = -50
  cur = cur - 12; // -50 - 12 = -62
  cur = cur + 15; // -62 + 15 = -47
  cur = cur - 6; // -47 - 6 = -53
  cur = cur - 19; // -53 - 19 = -72
  cur = cur - 18; // -72 - 18 = -90
  cur = cur - 20; // -90 - 20 = -110
  cur = cur + 12; // -110 + 12 = -98
  cur = cur - 21; // -98 - 21 = -119
  cur = cur - 21; // -119 - 21 = -140
  cur = cur - 10; // -140 - 10 = -150
  cur = cur - 20; // -150 - 20 = -170
  cur = cur - 31; // -170 - 31 = -201
  cur = cur + 4; // -201 + 4 = -197
  cur = cur + 26; // -197 + 26 = -171
  cur = cur - 16; // -171 - 16 = -187
  cur = cur - 21; // -187 - 21 = -208
  cur = cur + 33; // -208 + 33 = -175
  cur = cur + 10; // -175 + 10 = -165
  cur = cur - 13; // -165 - 13 = -178
  if (-178 != cur) exit(14);
  return cur;
}

int64_t check_14(int64_t cur) {
  if (0 == cur) exit(15);
  cur = cur + 32; // 111 + 32 = 143
  cur = cur + 33; // 143 + 33 = 176
  cur = cur + 19; // 176 + 19 = 195
  cur = cur + 10; // 195 + 10 = 205
  cur = cur - 6; // 205 - 6 = 199
  cur = cur - 5; // 199 - 5 = 194
  cur = cur - 10; // 194 - 10 = 184
  cur = cur + 33; // 184 + 33 = 217
  cur = cur + 4; // 217 + 4 = 221
  cur = cur + 16; // 221 + 16 = 237
  cur = cur + 22; // 237 + 22 = 259
  cur = cur - 31; // 259 - 31 = 228
  cur = cur + 31; // 228 + 31 = 259
  cur = cur - 26; // 259 - 26 = 233
  cur = cur - 29; // 233 - 29 = 204
  cur = cur + 5; // 204 + 5 = 209
  cur = cur - 3; // 209 - 3 = 206
  cur = cur - 13; // 206 - 13 = 193
  cur = cur + 20; // 193 + 20 = 213
  cur = cur - 33; // 213 - 33 = 180
  cur = cur - 24; // 180 - 24 = 156
  cur = cur + 11; // 156 + 11 = 167
  cur = cur + 19; // 167 + 19 = 186
  cur = cur - 27; // 186 - 27 = 159
  cur = cur + 25; // 159 + 25 = 184
  cur = cur - 24; // 184 - 24 = 160
  cur = cur - 31; // 160 - 31 = 129
  cur = cur - 13; // 129 - 13 = 116
  cur = cur - 13; // 116 - 13 = 103
  cur = cur + 28; // 103 + 28 = 131
  cur = cur - 14; // 131 - 14 = 117
  cur = cur + 29; // 117 + 29 = 146
  if (146 != cur) exit(15);
  return cur;
}

int64_t check_15(int64_t cur) {
  if (0 == cur) exit(16);
  cur = cur + 34; // 114 + 34 = 148
  cur = cur - 10; // 148 - 10 = 138
  cur = cur - 17; // 138 - 17 = 121
  cur = cur - 16; // 121 - 16 = 105
  cur = cur - 26; // 105 - 26 = 79
  cur = cur + 21; // 79 + 21 = 100
  cur = cur + 14; // 100 + 14 = 114
  cur = cur + 17; // 114 + 17 = 131
  cur = cur - 31; // 131 - 31 = 100
  cur = cur - 8; // 100 - 8 = 92
  cur = cur - 17; // 92 - 17 = 75
  cur = cur + 8; // 75 + 8 = 83
  cur = cur + 22; // 83 + 22 = 105
  cur = cur + 17; // 105 + 17 = 122
  cur = cur - 24; // 122 - 24 = 98
  cur = cur - 28; // 98 - 28 = 70
  cur = cur - 11; // 70 - 11 = 59
  cur = cur - 29; // 59 - 29 = 30
  cur = cur + 19; // 30 + 19 = 49
  cur = cur + 33; // 49 + 33 = 82
  cur = cur + 11; // 82 + 11 = 93
  cur = cur + 20; // 93 + 20 = 113
  cur = cur - 8; // 113 - 8 = 105
  cur = cur - 29; // 105 - 29 = 76
  cur = cur - 3; // 76 - 3 = 73
  cur = cur + 27; // 73 + 27 = 100
  cur = cur - 14; // 100 - 14 = 86
  cur = cur - 24; // 86 - 24 = 62
  cur = cur - 25; // 62 - 25 = 37
  cur = cur - 8; // 37 - 8 = 29
  cur = cur + 19; // 29 + 19 = 48
  cur = cur + 31; // 48 + 31 = 79
  if (79 != cur) exit(16);
  return cur;
}

int64_t check_16(int64_t cur) {
  if (0 == cur) exit(17);
  cur = cur - 26; // 101 - 26 = 75
  cur = cur - 27; // 75 - 27 = 48
  cur = cur - 22; // 48 - 22 = 26
  cur = cur - 7; // 26 - 7 = 19
  cur = cur + 13; // 19 + 13 = 32
  cur = cur - 18; // 32 - 18 = 14
  cur = cur + 14; // 14 + 14 = 28
  cur = cur - 4; // 28 - 4 = 24
  cur = cur - 27; // 24 - 27 = -3
  cur = cur - 19; // -3 - 19 = -22
  cur = cur - 31; // -22 - 31 = -53
  cur = cur - 20; // -53 - 20 = -73
  cur = cur + 22; // -73 + 22 = -51
  cur = cur - 28; // -51 - 28 = -79
  cur = cur + 32; // -79 + 32 = -47
  cur = cur - 32; // -47 - 32 = -79
  cur = cur + 24; // -79 + 24 = -55
  cur = cur - 34; // -55 - 34 = -89
  cur = cur + 10; // -89 + 10 = -79
  cur = cur - 30; // -79 - 30 = -109
  cur = cur + 25; // -109 + 25 = -84
  cur = cur - 6; // -84 - 6 = -90
  cur = cur + 14; // -90 + 14 = -76
  cur = cur + 9; // -76 + 9 = -67
  cur = cur - 19; // -67 - 19 = -86
  cur = cur + 14; // -86 + 14 = -72
  cur = cur - 29; // -72 - 29 = -101
  cur = cur + 17; // -101 + 17 = -84
  cur = cur + 7; // -84 + 7 = -77
  cur = cur - 18; // -77 - 18 = -95
  cur = cur - 9; // -95 - 9 = -104
  cur = cur - 18; // -104 - 18 = -122
  if (-122 != cur) exit(17);
  return cur;
}

int64_t check_17(int64_t cur) {
  if (0 == cur) exit(18);
  cur = cur - 18; // 32 - 18 = 14
  cur = cur - 31; // 14 - 31 = -17
  cur = cur - 17; // -17 - 17 = -34
  cur = cur + 7; // -34 + 7 = -27
  cur = cur + 11; // -27 + 11 = -16
  cur = cur - 27; // -16 - 27 = -43
  cur = cur - 19; // -43 - 19 = -62
  cur = cur + 33; // -62 + 33 = -29
  cur = cur - 22; // -29 - 22 = -51
  cur = cur - 29; // -51 - 29 = -80
  cur = cur + 33; // -80 + 33 = -47
  cur = cur - 9; // -47 - 9 = -56
  cur = cur - 29; // -56 - 29 = -85
  cur = cur - 13; // -85 - 13 = -98
  cur = cur - 31; // -98 - 31 = -129
  cur = cur + 15; // -129 + 15 = -114
  cur = cur + 27; // -114 + 27 = -87
  cur = cur + 19; // -87 + 19 = -68
  cur = cur - 24; // -68 - 24 = -92
  cur = cur + 14; // -92 + 14 = -78
  cur = cur + 19; // -78 + 19 = -59
  cur = cur + 29; // -59 + 29 = -30
  cur = cur + 13; // -30 + 13 = -17
  cur = cur + 8; // -17 + 8 = -9
  cur = cur + 12; // -9 + 12 = 3
  cur = cur + 33; // 3 + 33 = 36
  cur = cur - 6; // 36 - 6 = 30
  cur = cur + 7; // 30 + 7 = 37
  cur = cur - 6; // 37 - 6 = 31
  cur = cur - 15; // 31 - 15 = 16
  cur = cur + 9; // 16 + 9 = 25
  cur = cur + 22; // 25 + 22 = 47
  if (47 != cur) exit(18);
  return cur;
}

int64_t check_18(int64_t cur) {
  if (0 == cur) exit(19);
  cur = cur + 12; // 116 + 12 = 128
  cur = cur - 34; // 128 - 34 = 94
  cur = cur + 3; // 94 + 3 = 97
  cur = cur - 17; // 97 - 17 = 80
  cur = cur - 20; // 80 - 20 = 60
  cur = cur - 8; // 60 - 8 = 52
  cur = cur + 19; // 52 + 19 = 71
  cur = cur + 14; // 71 + 14 = 85
  cur = cur + 32; // 85 + 32 = 117
  cur = cur - 17; // 117 - 17 = 100
  cur = cur + 25; // 100 + 25 = 125
  cur = cur - 30; // 125 - 30 = 95
  cur = cur + 12; // 95 + 12 = 107
  cur = cur + 23; // 107 + 23 = 130
  cur = cur - 29; // 130 - 29 = 101
  cur = cur - 32; // 101 - 32 = 69
  cur = cur - 22; // 69 - 22 = 47
  cur = cur - 17; // 47 - 17 = 30
  cur = cur + 21; // 30 + 21 = 51
  cur = cur + 30; // 51 + 30 = 81
  cur = cur - 30; // 81 - 30 = 51
  cur = cur + 34; // 51 + 34 = 85
  cur = cur - 3; // 85 - 3 = 82
  cur = cur + 33; // 82 + 33 = 115
  cur = cur + 24; // 115 + 24 = 139
  cur = cur + 9; // 139 + 9 = 148
  cur = cur - 17; // 148 - 17 = 131
  cur = cur - 8; // 131 - 8 = 123
  cur = cur + 25; // 123 + 25 = 148
  cur = cur + 12; // 148 + 12 = 160
  cur = cur + 6; // 160 + 6 = 166
  cur = cur - 3; // 166 - 3 = 163
  if (163 != cur) exit(19);
  return cur;
}

int64_t check_19(int64_t cur) {
  if (0 == cur) exit(20);
  cur = cur + 19; // 97 + 19 = 116
  cur = cur - 14; // 116 - 14 = 102
  cur = cur - 24; // 102 - 24 = 78
  cur = cur + 20; // 78 + 20 = 98
  cur = cur + 4; // 98 + 4 = 102
  cur = cur - 32; // 102 - 32 = 70
  cur = cur + 29; // 70 + 29 = 99
  cur = cur + 21; // 99 + 21 = 120
  cur = cur - 14; // 120 - 14 = 106
  cur = cur + 11; // 106 + 11 = 117
  cur = cur + 23; // 117 + 23 = 140
  cur = cur - 8; // 140 - 8 = 132
  cur = cur - 24; // 132 - 24 = 108
  cur = cur + 26; // 108 + 26 = 134
  cur = cur + 3; // 134 + 3 = 137
  cur = cur + 22; // 137 + 22 = 159
  cur = cur - 28; // 159 - 28 = 131
  cur = cur - 15; // 131 - 15 = 116
  cur = cur + 4; // 116 + 4 = 120
  cur = cur - 8; // 120 - 8 = 112
  cur = cur - 24; // 112 - 24 = 88
  cur = cur + 24; // 88 + 24 = 112
  cur = cur + 25; // 112 + 25 = 137
  cur = cur - 14; // 137 - 14 = 123
  cur = cur - 24; // 123 - 24 = 99
  cur = cur + 19; // 99 + 19 = 118
  cur = cur - 26; // 118 - 26 = 92
  cur = cur - 22; // 92 - 22 = 70
  cur = cur - 3; // 70 - 3 = 67
  cur = cur + 34; // 67 + 34 = 101
  cur = cur - 17; // 101 - 17 = 84
  cur = cur + 14; // 84 + 14 = 98
  if (98 != cur) exit(20);
  return cur;
}

int64_t check_20(int64_t cur) {
  if (0 == cur) exit(21);
  cur = cur + 17; // 107 + 17 = 124
  cur = cur - 20; // 124 - 20 = 104
  cur = cur + 20; // 104 + 20 = 124
  cur = cur - 34; // 124 - 34 = 90
  cur = cur + 27; // 90 + 27 = 117
  cur = cur + 13; // 117 + 13 = 130
  cur = cur + 22; // 130 + 22 = 152
  cur = cur - 3; // 152 - 3 = 149
  cur = cur - 19; // 149 - 19 = 130
  cur = cur - 22; // 130 - 22 = 108
  cur = cur + 20; // 108 + 20 = 128
  cur = cur - 3; // 128 - 3 = 125
  cur = cur + 19; // 125 + 19 = 144
  cur = cur - 19; // 144 - 19 = 125
  cur = cur + 10; // 125 + 10 = 135
  cur = cur + 15; // 135 + 15 = 150
  cur = cur - 30; // 150 - 30 = 120
  cur = cur - 16; // 120 - 16 = 104
  cur = cur + 4; // 104 + 4 = 108
  cur = cur - 8; // 108 - 8 = 100
  cur = cur + 22; // 100 + 22 = 122
  cur = cur - 16; // 122 - 16 = 106
  cur = cur - 5; // 106 - 5 = 101
  cur = cur + 18; // 101 + 18 = 119
  cur = cur - 3; // 119 - 3 = 116
  cur = cur + 9; // 116 + 9 = 125
  cur = cur - 17; // 125 - 17 = 108
  cur = cur - 7; // 108 - 7 = 101
  cur = cur + 17; // 101 + 17 = 118
  cur = cur - 31; // 118 - 31 = 87
  cur = cur + 33; // 87 + 33 = 120
  cur = cur + 7; // 120 + 7 = 127
  if (127 != cur) exit(21);
  return cur;
}

int64_t check_21(int64_t cur) {
  if (0 == cur) exit(22);
  cur = cur - 9; // 105 - 9 = 96
  cur = cur - 24; // 96 - 24 = 72
  cur = cur + 29; // 72 + 29 = 101
  cur = cur + 16; // 101 + 16 = 117
  cur = cur - 11; // 117 - 11 = 106
  cur = cur - 20; // 106 - 20 = 86
  cur = cur - 33; // 86 - 33 = 53
  cur = cur + 19; // 53 + 19 = 72
  cur = cur + 27; // 72 + 27 = 99
  cur = cur + 3; // 99 + 3 = 102
  cur = cur + 18; // 102 + 18 = 120
  cur = cur + 22; // 120 + 22 = 142
  cur = cur - 4; // 142 - 4 = 138
  cur = cur - 9; // 138 - 9 = 129
  cur = cur + 13; // 129 + 13 = 142
  cur = cur + 28; // 142 + 28 = 170
  cur = cur - 33; // 170 - 33 = 137
  cur = cur - 21; // 137 - 21 = 116
  cur = cur + 19; // 116 + 19 = 135
  cur = cur - 7; // 135 - 7 = 128
  cur = cur - 29; // 128 - 29 = 99
  cur = cur + 9; // 99 + 9 = 108
  cur = cur - 8; // 108 - 8 = 100
  cur = cur + 13; // 100 + 13 = 113
  cur = cur + 19; // 113 + 19 = 132
  cur = cur - 22; // 132 - 22 = 110
  cur = cur + 31; // 110 + 31 = 141
  cur = cur + 9; // 141 + 9 = 150
  cur = cur - 8; // 150 - 8 = 142
  cur = cur - 9; // 142 - 9 = 133
  cur = cur - 25; // 133 - 25 = 108
  cur = cur - 33; // 108 - 33 = 75
  if (75 != cur) exit(22);
  return cur;
}

int64_t check_22(int64_t cur) {
  if (0 == cur) exit(23);
  cur = cur - 30; // 110 - 30 = 80
  cur = cur - 14; // 80 - 14 = 66
  cur = cur - 22; // 66 - 22 = 44
  cur = cur - 34; // 44 - 34 = 10
  cur = cur + 33; // 10 + 33 = 43
  cur = cur - 4; // 43 - 4 = 39
  cur = cur + 28; // 39 + 28 = 67
  cur = cur - 16; // 67 - 16 = 51
  cur = cur - 19; // 51 - 19 = 32
  cur = cur + 27; // 32 + 27 = 59
  cur = cur + 20; // 59 + 20 = 79
  cur = cur + 4; // 79 + 4 = 83
  cur = cur + 27; // 83 + 27 = 110
  cur = cur + 3; // 110 + 3 = 113
  cur = cur - 17; // 113 - 17 = 96
  cur = cur + 31; // 96 + 31 = 127
  cur = cur - 13; // 127 - 13 = 114
  cur = cur - 9; // 114 - 9 = 105
  cur = cur - 31; // 105 - 31 = 74
  cur = cur + 20; // 74 + 20 = 94
  cur = cur + 10; // 94 + 10 = 104
  cur = cur - 3; // 104 - 3 = 101
  cur = cur - 20; // 101 - 20 = 81
  cur = cur - 15; // 81 - 15 = 66
  cur = cur + 6; // 66 + 6 = 72
  cur = cur - 23; // 72 - 23 = 49
  cur = cur - 13; // 49 - 13 = 36
  cur = cur + 15; // 36 + 15 = 51
  cur = cur - 33; // 51 - 33 = 18
  cur = cur + 27; // 18 + 27 = 45
  cur = cur + 5; // 45 + 5 = 50
  cur = cur - 26; // 50 - 26 = 24
  if (24 != cur) exit(23);
  return cur;
}

int64_t check_23(int64_t cur) {
  if (0 == cur) exit(24);
  cur = cur + 7; // 103 + 7 = 110
  cur = cur + 21; // 110 + 21 = 131
  cur = cur + 31; // 131 + 31 = 162
  cur = cur + 10; // 162 + 10 = 172
  cur = cur + 14; // 172 + 14 = 186
  cur = cur - 21; // 186 - 21 = 165
  cur = cur + 4; // 165 + 4 = 169
  cur = cur + 34; // 169 + 34 = 203
  cur = cur - 6; // 203 - 6 = 197
  cur = cur - 6; // 197 - 6 = 191
  cur = cur + 23; // 191 + 23 = 214
  cur = cur + 31; // 214 + 31 = 245
  cur = cur + 26; // 245 + 26 = 271
  cur = cur - 33; // 271 - 33 = 238
  cur = cur - 6; // 238 - 6 = 232
  cur = cur + 10; // 232 + 10 = 242
  cur = cur + 14; // 242 + 14 = 256
  cur = cur + 30; // 256 + 30 = 286
  cur = cur + 12; // 286 + 12 = 298
  cur = cur - 11; // 298 - 11 = 287
  cur = cur - 22; // 287 - 22 = 265
  cur = cur - 4; // 265 - 4 = 261
  cur = cur + 27; // 261 + 27 = 288
  cur = cur - 16; // 288 - 16 = 272
  cur = cur + 6; // 272 + 6 = 278
  cur = cur + 34; // 278 + 34 = 312
  cur = cur - 4; // 312 - 4 = 308
  cur = cur + 16; // 308 + 16 = 324
  cur = cur - 28; // 324 - 28 = 296
  cur = cur + 8; // 296 + 8 = 304
  cur = cur - 26; // 304 - 26 = 278
  cur = cur + 14; // 278 + 14 = 292
  if (292 != cur) exit(24);
  return cur;
}

int64_t check(char* got) {
  int64_t sum = 0;
  sum += check_0(got[0]); // 0 + 6 = 6
  sum >>= 3; // 6 >> 3 = 0
  sum += check_1(got[1]); // 0 + 169 = 169
  sum >>= 3; // 169 >> 3 = 21
  sum += check_2(got[2]); // 21 + 121 = 142
  sum >>= 3; // 142 >> 3 = 17
  sum += check_3(got[3]); // 17 + 262 = 279
  sum >>= 3; // 279 >> 3 = 34
  sum += check_4(got[4]); // 34 + 76 = 110
  sum >>= 3; // 110 >> 3 = 13
  sum += check_5(got[5]); // 13 + -15 = -2
  sum >>= 3; // -2 >> 3 = -1
  sum += check_6(got[6]); // -1 + 64 = 63
  sum >>= 3; // 63 >> 3 = 7
  sum += check_7(got[7]); // 7 + -34 = -27
  sum >>= 3; // -27 >> 3 = -4
  sum += check_8(got[8]); // -4 + -40 = -44
  sum >>= 3; // -44 >> 3 = -6
  sum += check_9(got[9]); // -6 + 155 = 149
  sum >>= 3; // 149 >> 3 = 18
  sum += check_10(got[10]); // 18 + -48 = -30
  sum >>= 3; // -30 >> 3 = -4
  sum += check_11(got[11]); // -4 + 143 = 139
  sum >>= 3; // 139 >> 3 = 17
  sum += check_12(got[12]); // 17 + -128 = -111
  sum >>= 3; // -111 >> 3 = -14
  sum += check_13(got[13]); // -14 + -178 = -192
  sum >>= 3; // -192 >> 3 = -24
  sum += check_14(got[14]); // -24 + 146 = 122
  sum >>= 3; // 122 >> 3 = 15
  sum += check_15(got[15]); // 15 + 79 = 94
  sum >>= 3; // 94 >> 3 = 11
  sum += check_16(got[16]); // 11 + -122 = -111
  sum >>= 3; // -111 >> 3 = -14
  sum += check_17(got[17]); // -14 + 47 = 33
  sum >>= 3; // 33 >> 3 = 4
  sum += check_18(got[18]); // 4 + 163 = 167
  sum >>= 3; // 167 >> 3 = 20
  sum += check_19(got[19]); // 20 + 98 = 118
  sum >>= 3; // 118 >> 3 = 14
  sum += check_20(got[20]); // 14 + 127 = 141
  sum >>= 3; // 141 >> 3 = 17
  sum += check_21(got[21]); // 17 + 75 = 92
  sum >>= 3; // 92 >> 3 = 11
  sum += check_22(got[22]); // 11 + 24 = 35
  sum >>= 3; // 35 >> 3 = 4
  sum += check_23(got[23]); // 4 + 292 = 296
  sum >>= 3; // 296 >> 3 = 37
  if (37 != sum) exit(250);
  return sum;
}
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>

#define CODE_LEN 80

int main() {
  char* code = calloc(sizeof(char), CODE_LEN + 1);

  puts("enter code:");
  fflush(stdout);

  fgets(code, CODE_LEN, stdin);

  long sum = check(code);

  printf("sum is %ld\n", sum);

  return 0;
}
