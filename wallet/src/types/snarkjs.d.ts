// Minimal ambient types for snarkjs 0.7.5 (ships no TypeScript declarations).
// Only the Groth16 surface the wallet uses is declared.
declare module "snarkjs" {
  export namespace groth16 {
    function fullProve(
      input: Record<string, unknown>,
      wasmFile: string,
      zkeyFile: string,
    ): Promise<{ proof: unknown; publicSignals: string[] }>;

    function verify(
      vk: unknown,
      publicSignals: string[],
      proof: unknown,
    ): Promise<boolean>;
  }
}
