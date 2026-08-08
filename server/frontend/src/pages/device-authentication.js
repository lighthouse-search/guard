"use client"
import "../../styles/global.css";
import Device_authentication1 from '../components/login/pages/device_authentication1';
import './../components/login/pages/css/magiclink1.css';
import Base from "@/components/base";

// Opened by the Guard desktop app as:
//   /guard/frontend/device-authentication?state=<deeplink_state>&public_key=<b64>&code=<display_code>
// The desktop generates its own keypair and keeps the private key in secure
// storage; this page only authenticates the user and registers the public key,
// then deeplinks the resulting device_id back to the app.
export default function Device_authentication() {
  return (
    <Base>
      <Device_authentication1/>
    </Base>
  )
}
