import Form from "@/components/Form";

/** Shown after a magiclink has been sent. */
export default function CheckYourEmail() {
  return (
    <Form className="magiclink_form" style={{ rowGap: 5 }}>
      <img className="magiclink_img" src="/guard/frontend/assets/magiclink.png" alt="" />
      <h2 className="magiclink_checkyouremail">Check your email</h2>
      <p className="magiclink_wesentalink">
        We&apos;ve sent you a Magiclink to authenticate with. <b>Remember to check your junk/spam folder.</b>
      </p>
    </Form>
  );
}
