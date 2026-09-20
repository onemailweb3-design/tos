// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later

/**
 * Poseidon2 t=8 over the BLS12-381 scalar field, section 4's hash.
 *
 * The parameters are generated, never transcribed: `generated/` comes out of
 * `crypto/poseidon2/manifest-gen`, which runs the pinned upstream reference.
 * A fifth hand-written copy of 65 round-constant rows would be a fifth chance
 * to mistype one, and the one that is mistyped is always the one nobody
 * checks.
 *
 * What is written by hand here is the permutation, and it is checked against
 * the same known-answer vectors the two VMs are checked against.
 */

import {
  DOMAINS,
  MAT_DIAG8,
  MODULUS,
  RC8,
  ROUNDS_F_BEGINNING,
  ROUNDS_P,
  ROUNDS_TOTAL,
  STATE_WIDTH,
} from "./generated/poseidon2-params.js";

/** A field element. Always reduced, never negative. */
export type Fr = bigint;

export function add(a: Fr, b: Fr): Fr {
  const sum = a + b;
  return sum >= MODULUS ? sum - MODULUS : sum;
}

export function mul(a: Fr, b: Fr): Fr {
  return (a * b) % MODULUS;
}

/** x^5, the s-box. */
function sbox(x: Fr): Fr {
  const squared = mul(x, x);
  return mul(mul(squared, squared), x);
}

/** The 4x4 block the external matrix is built from. */
function matmulM4(x: Fr[], at: number): void {
  const t0 = add(x[at], x[at + 1]);
  const t1 = add(x[at + 2], x[at + 3]);
  const t2 = add(add(x[at + 1], x[at + 1]), t1);
  const t3 = add(add(x[at + 3], x[at + 3]), t0);
  const fourT1 = add(add(t1, t1), add(t1, t1));
  const t4 = add(fourT1, t3);
  const fourT0 = add(add(t0, t0), add(t0, t0));
  const t5 = add(fourT0, t2);
  x[at] = add(t3, t5);
  x[at + 1] = t5;
  x[at + 2] = add(t2, t4);
  x[at + 3] = t4;
}

function matmulExternal(s: Fr[]): void {
  matmulM4(s, 0);
  matmulM4(s, 4);
  const stored = [0n, 0n, 0n, 0n];
  for (let lane = 0; lane < 4; lane += 1) {
    stored[lane] = add(s[lane], s[4 + lane]);
  }
  for (let lane = 0; lane < STATE_WIDTH; lane += 1) {
    s[lane] = add(s[lane], stored[lane % 4]);
  }
}

function matmulInternal(s: Fr[]): void {
  let sum = s[0];
  for (let lane = 1; lane < STATE_WIDTH; lane += 1) {
    sum = add(sum, s[lane]);
  }
  for (let lane = 0; lane < STATE_WIDTH; lane += 1) {
    s[lane] = add(mul(s[lane], MAT_DIAG8[lane]), sum);
  }
}

/** The permutation: eight full rounds around fifty-seven partial ones. */
export function permute(state: readonly Fr[]): Fr[] {
  if (state.length !== STATE_WIDTH) {
    throw new Error(`a Poseidon2 state is ${STATE_WIDTH} elements, not ${state.length}`);
  }
  const s = state.map((value) => ((value % MODULUS) + MODULUS) % MODULUS);

  matmulExternal(s);
  const partialEnd = ROUNDS_F_BEGINNING + ROUNDS_P;
  for (let round = 0; round < ROUNDS_F_BEGINNING; round += 1) {
    for (let lane = 0; lane < STATE_WIDTH; lane += 1) {
      s[lane] = sbox(add(s[lane], RC8[round][lane]));
    }
    matmulExternal(s);
  }
  for (let round = ROUNDS_F_BEGINNING; round < partialEnd; round += 1) {
    s[0] = sbox(add(s[0], RC8[round][0]));
    matmulInternal(s);
  }
  for (let round = partialEnd; round < ROUNDS_TOTAL; round += 1) {
    for (let lane = 0; lane < STATE_WIDTH; lane += 1) {
      s[lane] = sbox(add(s[lane], RC8[round][lane]));
    }
    matmulExternal(s);
  }
  return s;
}

/**
 * Section 4's `H7`: a domain constant in lane zero, seven arguments after it,
 * and the first lane of the result.
 */
export function h7(label: string, args: readonly Fr[]): Fr {
  if (args.length !== 7) {
    throw new Error(`H7 takes seven arguments, not ${args.length}`);
  }
  const domain = DOMAINS[label];
  if (domain === undefined) {
    throw new Error(`no domain constant named ${label}`);
  }
  return permute([domain, ...args])[0];
}

/**
 * The fixed owner hash a dummy output names instead of a real one. Section
 * 1.4: it is the domain constant itself, not a hash taken over anything.
 */
export function dummyOwnerNfHash(): Fr {
  const value = DOMAINS["DUMMY-OWNER-NF"];
  if (value === undefined) {
    throw new Error("the dummy owner domain constant is missing");
  }
  return value;
}
