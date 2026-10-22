interface BackgroundImageProps {
  src: string;
}

/**
 * Full-bleed background image, used by the split login layout.
 *
 * A plain <img> rather than next/image: this app is a static export, so there
 * is no server to do the optimisation (`images.unoptimized` in next.config.ts).
 */
export default function BackgroundImage({ src }: BackgroundImageProps) {
  return (
    <div className="image_background">
      <img className="image" src={src} alt="" />
    </div>
  );
}
