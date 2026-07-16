declare module "murmurhash3js-revisited" {
  const MurmurHash3: {
    x86: {
      hash32(bytes: ArrayLike<number>, seed?: number): number | undefined;
    };
  };

  export default MurmurHash3;
}
