"use client";
import LoginForm from "@/components/LoginForm";
import MetadataPanelFrame from "@/components/MetadataPanelFrame";
import type { LoginMetadata } from "@/types";

interface LoginScreenProps {
  metadata: LoginMetadata;
}

/** The default login layout (`style = "login_1"`): branding panel beside the form. */
export default function LoginScreen({ metadata }: LoginScreenProps) {
  return (
    <MetadataPanelFrame metadata={metadata}>
      <LoginForm metadata={metadata} header={metadata.login_header} />
    </MetadataPanelFrame>
  );
}
