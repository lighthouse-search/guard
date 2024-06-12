import Login1_special from '@/components/login/pages/login1_special'
import "../../styles/global.css";
import { useEffect, useRef, useState } from 'react';
import Base from '@/components/base';
import { is_authenticated } from '@/global';
import { redirect } from 'next/navigation';
import { useRouter } from 'next/router';

export default function Login() {
  const router = useRouter();
  const shouldSend = useRef(true);
  const [metadata, set_metadata] = useState(null);

  async function check_logged_in() {
    const params = new URLSearchParams(document.location.search);

    if (await is_authenticated() == true) {
      router.push(`/access-denied?${params.toString()}`);
      return;
    }
  }

  useEffect(() => {
    if (shouldSend.current != true) { return; }
    shouldSend.current = false;

    check_logged_in()
  });

  return (
    <Base metadata={metadata} style={{ width: "100%", height: "100vh", overflow: "hidden", alignItems: "center", justifyContent: "center" }}>
      <Login1_special set_metadata={set_metadata}/>
    </Base>
  )
}