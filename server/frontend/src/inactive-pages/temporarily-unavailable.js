"use client"
import "../../styles/global.css";
import './css/access-denied.css';
import Login1 from '../components/login/pages/login1';
import './../components/login/pages/css/magiclink1.css';
import FormStyle_1 from "@/components/login/forms/form_style1";
import { useEffect, useRef, useState } from 'react';

export default function Temporarily_unavailable(props) {
    return (
        <div style={{ width: "100%", height: "100vh", overflow: "hidden", alignItems: "center", justifyContent: "center" }}>
            <Login1>
                <FormStyle_1 header={false} className="access_denied_form" style={{ rowGap: 5 }}>
                    {/* <img className='magiclink_img' src="/assets/crystalball.png"/> */}
                    <h2 className='access_denied_header'>Temporarily unavailable</h2>
                    <p className='access_denied_subtext'>Sorry, looks like my configuration is out-of-date. The administrators have been notified, and I should be back soon.</p>
                </FormStyle_1>
            </Login1>
        </div>
    )
}