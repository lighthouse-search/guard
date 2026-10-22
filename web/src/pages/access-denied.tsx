import Base from "@/components/Base";

/** Shown when a user authenticated successfully but policy refused them. */
export default function AccessDenied() {
  return (
    <Base>
      <div className="flex items-center justify-center w-full h-screen bg-[rgb(235,235,235)]">
        <div className="flex flex-col items-center gap-4 bg-white rounded p-6 w-[400px] shadow-sm">
          <div className="flex flex-col items-center gap-1 text-center">
            <h1 className="text-xl font-bold">Access denied</h1>
            <p className="text-sm text-gray-500">
              You are not authorised to access {typeof window !== "undefined" ? window.location.hostname : ""}
            </p>
          </div>
        </div>
      </div>
    </Base>
  );
}
