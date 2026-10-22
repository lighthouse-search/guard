import type { AppProps } from "next/app";
import Head from "next/head";
import { useRouter } from "next/router";
import { Roboto } from "next/font/google";

// Every stylesheet in this app is global (plain CSS, not CSS Modules), and the
// Pages Router only permits global CSS to be imported from here. Keeping them
// in one list also makes the cascade order explicit, instead of depending on
// which component happened to be imported first.
import "@/styles/global.css";

import "@/components/Base.css";
import "@/components/BackgroundImage.css";
import "@/components/DeviceCodePrompt.css";
import "@/components/Form.css";
import "@/components/LabelledInput.css";
import "@/components/LoadingScreen.css";
import "@/components/LoadingSpinner.css";
import "@/components/LoginWithButton.css";
import "@/components/MetadataPanel.css";
import "@/components/OrBar.css";

import "@/screens/LoginSplitScreen.css";
import "@/screens/MagiclinkScreen.css";

import "@/pages/oauth/authorise.css";

const roboto = Roboto({
  subsets: ["latin"],
  weight: ["400", "700"],
});

export default function App({ Component, pageProps }: AppProps) {
  const { basePath } = useRouter();

  return (
    // display:contents applies the font to the whole page without introducing a
    // layout box, so the page shell still measures against the viewport.
    <div className={roboto.className} style={{ display: "contents" }}>
      <Head>
        {/* Default title; the login page replaces it with the instance's name. */}
        <title>Guard</title>
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        <link rel="icon" href={`${basePath}/favicon.ico`} />
      </Head>
      <Component {...pageProps} />
    </div>
  );
}
