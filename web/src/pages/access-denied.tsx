import Base from "@/components/Base";
import { useHostname } from "@/lib/hostname";

/** Shown when a user authenticated successfully but policy refused them. */
export default function AccessDenied() {
  const hostname = useHostname();

  return (
    <Base>
      <div className="flex items-center justify-center w-full h-screen">
        <div className="flex flex-col items-center gap-4 rounded p-6 w-[400px] card_surface">
          <div className="flex flex-col items-center gap-1 text-center">
            <h1 className="text-xl font-bold">Access denied</h1>
            <p className="text-sm muted_text">
              You're not authorised to access {hostname ?? "this site"}
            </p>
          </div>
        </div>
      </div>
    </Base>
  );
}
