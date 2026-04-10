import React, { useEffect, useRef, useState } from 'react';
import Base from '@/components/base';
import { useRouter } from 'next/router';
import "../../styles/global.css";
import { Turnstile } from '@marsidev/react-turnstile';

export default function Login() {
  const router = useRouter();
  const shouldSend = useRef(true);
  const [metadata, set_metadata] = useState(null);

  const turnstileRef = useRef(null)

  async function handleSubmit(e) {
    e.preventDefault()
    const token = turnstileRef.current?.getResponse()
    // Send token to your server...
    turnstileRef.current?.reset() // Reset after submission
  }

  return (
    <Base metadata={metadata}>
      <div className="flex items-center justify-center w-full h-screen bg-[rgb(235,235,235)]">
        <div className="flex flex-col items-center gap-4 bg-white rounded p-6 w-[400px] shadow-sm">
          <div className="flex flex-col items-center gap-1 text-center">
            <h1 className="text-xl font-bold">Are you a robot?</h1>
            <p className="text-sm text-gray-500">{typeof window != "undefined" && window.location.hostname || ""} will continue after captcha.</p>
          </div>
          <Turnstile
            ref={turnstileRef}
            siteKey=''
          />
        </div>
      </div>
    </Base>
  )
}