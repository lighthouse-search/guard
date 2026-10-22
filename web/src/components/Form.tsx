import type { CSSProperties, ReactNode } from "react";

interface FormProps {
  children?: ReactNode;
  className?: string;
  style?: CSSProperties;
  header?: ReactNode;
  description?: ReactNode;
  logo?: ReactNode;
}

/**
 * The bordered card every login screen is built inside: an optional
 * header/description/logo block, then whatever the screen puts in it.
 */
export default function Form({ children, className, style, header, description, logo }: FormProps) {
  const hasHeading = Boolean(header || description || logo);

  return (
    <div className={`FormStyle_1 ${className ?? ""}`} style={style}>
      {hasHeading && (
        <div className="column row_gap_4">
          {logo && <div className="FormStyle_1_logo">{logo}</div>}
          {header && <h1 className="FormStyle_1_header">{header}</h1>}
          {description && <p className="FormStyle_1_description">{description}</p>}
        </div>
      )}
      {children}
    </div>
  );
}
