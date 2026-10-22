import { useState } from "react";
import Form from "@/components/Form";

interface DeviceCodePromptProps {
  /** The code the desktop app is displaying. */
  code: string | null;
  onSuccess?: () => void;
  onFailure?: () => void;
}

/**
 * Asks the user to type the code the desktop app is showing.
 *
 * This is an anti-phishing step: it proves the person at the browser is the
 * person at the app, so a link alone cannot authorise a device.
 */
export default function DeviceCodePrompt({ code, onSuccess, onFailure }: DeviceCodePromptProps) {
  const [error, setError] = useState<string | null>(null);
  const [entered, setEntered] = useState("");

  function verifyCode() {
    setError(null);

    if (code !== null && entered === code) {
      onSuccess?.();
      return;
    }

    setError("Incorrect code");
    onFailure?.();
  }

  return (
    <Form className="desktop_application_form row_gap_6">
      {error && <p className="FormStyle_1_div_error">{error}</p>}
      <div className="column row_gap_2">
        <h2 className="desktop_application_header">Authenticating Desktop Application</h2>
        <p className="desktop_application_subtext">
          You&apos;re authenticating a Guard Desktop Application. Please enter the displayed code. If you
          don&apos;t intend to do this, you can safely close this page.
        </p>
      </div>
      <input
        placeholder="Code"
        value={entered}
        onChange={(event) => setEntered(event.target.value)}
        onKeyDown={(event) => {
          if (event.key === "Enter") {
            verifyCode();
          }
        }}
      />
      <button onClick={verifyCode}>Authenticate</button>
    </Form>
  );
}
