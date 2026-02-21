import Input from "./Input";

export default function HostnameComponent(props: any) {
    return (
        <div className="flex flex-col gap-y-4 p-5">
            {/* TODO: Add "active" switch. */}
            <Input optional={true} header="Hostname" placeholder="sydney.example.com"/>
            <Input optional={true} header="Alias" placeholder="Sydney"/>
            <div className="flex flex-col">
              <h3>Authentication methods</h3>
              <a>Add authentication method</a>
            </div>
            {/* TODO: Add "multistep authentication" switch. */}
            <div className="flex flex-col">
              <h3>Applied policies</h3>
              <a>Add authentication method</a>
            </div>
        </div>
    )
}