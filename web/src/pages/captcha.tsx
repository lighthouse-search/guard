import { Turnstile } from "@marsidev/react-turnstile";
import Base from "@/components/Base";

/**
 * Captcha interstitial.
 *
 * Prototype: `siteKey` still needs to come from instance config, and the token
 * is not yet submitted anywhere for verification.
 */
export default function Captcha() {
  return (
    <Base>
      <div className="flex items-center justify-center w-full h-screen bg-[rgb(235,235,235)]">
        <div className="flex flex-col items-center gap-4 bg-white rounded p-6 w-[400px] shadow-sm">
          <div className="flex flex-col items-center gap-1 text-center">
            <h1 className="text-xl font-bold">Are you a robot?</h1>
            <p className="text-sm text-gray-500">
              {typeof window !== "undefined" ? window.location.hostname : ""} will continue after captcha.
            </p>
          </div>
          <Turnstile siteKey="" />
        </div>
      </div>
    </Base>
  );
}
