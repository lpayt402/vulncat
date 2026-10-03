/** Original, repository-native mark. Decorative wherever the adjacent wordmark names the app. */
export function CatMark({ size = 38 }: { size?: number }) {
  return <img className="vb-cat-mark" src="/spoopy-cat.svg" width={size} height={size} alt="" aria-hidden="true" />;
}
