import { Turnstile } from "@marsidev/react-turnstile";
import Base from "@/components/Base";
import { useHostname } from "@/lib/hostname";

/**
 * Captcha interstitial.
 *
 * Prototype: `siteKey` still needs to come from instance config, and the token
 * is not yet submitted anywhere for verification.
 */
export default function Captcha() {
  const hostname = useHostname();

  return (
    <Base>
      <div className="flex items-center justify-center w-full h-screen">
        <div className="flex flex-col items-center gap-4 rounded p-6 w-[400px] card_surface">
          <div className="flex flex-col items-center gap-1 text-center">
            <h1 className="text-xl font-bold">Are you a robot?</h1>
            <p className="text-sm muted_text">
              {hostname ?? "This site"} will continue after captcha.
            </p>
          </div>
          <Turnstile siteKey="" />
        </div>
      </div>
    </Base>
  );
}
