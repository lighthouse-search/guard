"use client";
import { useEffect, useRef, useState } from "react";
import { useRouter } from "next/router";
import Form from "@/components/Form";
import MetadataPanelFrame from "@/components/MetadataPanelFrame";
import { logout, readCredentials } from "@/lib/session";

/** Asks the user to confirm signing out. */
export default function LogoutScreen() {
  const router = useRouter();
  const shouldRun = useRef(true);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (!shouldRun.current) {
      return;
    }
    shouldRun.current = false;

    // Nothing to log out of — send them to the login page instead.
    if (!readCredentials()) {
      void router.push("/login");
      return;
    }

    setLoading(false);
  }, [router]);

  return (
    <MetadataPanelFrame>
      {!loading && (
        <Form header="Logout">
          <div className="FormStyle_1_div">
            <button onClick={() => logout()} className="FormStyle_1_div_login_button">Yes</button>
            <button onClick={() => window.close()} className="FormStyle_1_div_login_button">No</button>
          </div>
        </Form>
      )}
    </MetadataPanelFrame>
  );
}
