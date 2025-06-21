import FormStyle_1 from '../form_style1';

export default function Check_your_email(props) { 
    return (
        <FormStyle_1 header={false} className="magiclink_form" style={{ rowGap: 5 }}>
            <img className='magiclink_img' src="/guard/frontend/assets/magiclink.png"/>
            <h2 className='magiclink_checkyouremail'>Check your email</h2>
            <p className='magiclink_wesentalink'>We've sent you a Magiclink to authenticate with. <b>Remember to check your junk/spam folder.</b></p>
        </FormStyle_1>
    )
};