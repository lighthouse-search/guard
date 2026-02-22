import ConfigApp from "@/pages/components/ConfigApp";
import { Metadata } from "next";

export const metadata: Metadata = {
  title: 'Config Creator | Guard',
};

export default function Home() {
  return <ConfigApp />;
}
