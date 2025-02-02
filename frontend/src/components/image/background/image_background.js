import './css/image_background.css';

export default function Image_background(props) {
    return (
        <div className='image_background'>
            <img className='image' src={props.src}/>
        </div>
    )
}