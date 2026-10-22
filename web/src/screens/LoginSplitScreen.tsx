"use client";
import BackgroundImage from "@/components/BackgroundImage";
import LoginForm from "@/components/LoginForm";
import type { LoginMetadata } from "@/types";

interface LoginSplitScreenProps {
  metadata: LoginMetadata;
}

/**
 * The alternate login layout (`style = "login_2"`): the form centred over a
 * full-bleed background image, with the instance's branding in the form itself.
 *
 * The centring comes from the `login2` class, which the page puts on `Base` —
 * it has to sit on the element that fills the viewport.
 */
export default function LoginSplitScreen({ metadata }: LoginSplitScreenProps) {
  return (
    <>
      {metadata.image && <BackgroundImage src={metadata.image} />}
      <div className="column">
        <LoginForm
          metadata={metadata}
          header={metadata.alias}
          description={metadata.public_description}
          logoUrl={metadata.logo}
        />
      </div>
    </>
  );
}
