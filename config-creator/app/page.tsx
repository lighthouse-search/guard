import ConfigEditor from "@/pages/components/ConfigEditor";
import HostnameComponent from "@/pages/components/Hostname";
import Input from "@/pages/components/Input";
import { Metadata } from "next";

export const metadata: Metadata = {
  title: 'Config Creator | Guard',
  // description: 'The official Next.js Course Dashboard, built with App Router.',
  // metadataBase: new URL('https://next-learn-dashboard.vercel.sh'),
};

export default function Home() {
  const hostnameUl = [0, 1, 2, 3].map((props: any) => {
    return (
      <HostnameComponent/>
    )
  });
  
  return (
    <div className="flex justify-between bg-zinc-50 font-sans dark:bg-black overflow-y-hidden h-screen">
      <div className="flex flex-col w-full p-4 gap-y-10 overflow-y-scroll">
        <h1 className="text-[20px] font-bold">Guard configuration creator</h1>

        <div className="flex flex-col gap-y-4">
          <h2>Features</h2>

          {/* TODO: add switches here. */}
          <Input type="checkbox" header="Request proxy"/>
          <Input type="checkbox" header="Reverse proxy authentication"/>
          <Input type="checkbox" header="OAuth server"/>
          <Input type="checkbox" header="TLS"/>
        </div>

        <div className="flex flex-col gap-y-4">
          <h2>Global styling</h2>
          <Input optional={true} header="Image" placeholder="https://example.com/company-logo-512px.png"/>
          <Input optional={true} header="Alias" placeholder="e.g. Grafana, Gitlab, Bitwarden or [company name]"/>
          <Input optional={true} header="Public description" placeholder="You're accessing sensitive information. Please login."/>

          {/* Email input */}
          <Input optional={true} header="Username placeholder" placeholder="john.doe"/>
          <Input optional={true} header="Domain placeholder" placeholder="example.com"/>
        </div>

        <div className="flex flex-col gap-y-4">
          <h2>MySQL</h2>
          <Input optional={true} header="Hostname" placeholder="sql.internal.example.com"/>
          <Input optional={true} header="Port" placeholder="3306"/>
          <Input optional={true} header="Username" placeholder="user"/>
          <Input optional={true} header="Password environment variable" placeholder="user_mysql_password"/>
          <Input optional={true} header="Database" placeholder="guard"/>
        </div>

        <div className="flex flex-col gap-y-4">
          <h2>SQL</h2>
          <Input optional={true} header="Users" placeholder="users"/>
          <Input optional={true} header="Devices" placeholder="devices"/>
          <Input optional={true} header="Magiclinks" placeholder="magiclinks"/>
        </div>

        <div className="flex flex-col gap-y-4">
          <h2>SMTP</h2>
          <Input optional={true} header="Host" placeholder="smtp.example.com"/>
          <Input optional={true} header="Port" placeholder="587"/>
          <Input optional={true} header="Username" placeholder="apikey"/>
          <Input optional={true} header="Password environment variable" placeholder="user_mysql_password"/>
          <Input optional={true} header="Sender name" placeholder="Guard"/>
          <Input optional={true} header="Sender address" placeholder="noreply@example.com"/>
          <Input optional={true} header="Reply-to address" placeholder="support@example.com"/>
        </div>

        <div className="flex flex-col gap-y-4">
          <h2>Hostnames</h2>

          {hostnameUl}

          <button>Add hostname</button>
        </div>
      </div>

      <div className="overflow-y-auto h-full">
        <ConfigEditor />
      </div>
    </div>
  );
}
