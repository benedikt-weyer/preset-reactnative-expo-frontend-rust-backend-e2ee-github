import type { Metadata } from "next";
import { Fraunces, Space_Grotesk } from "next/font/google";
import Script from "next/script";

import "./globals.css";

const sans = Space_Grotesk({
  subsets: ["latin"],
  variable: "--font-space-grotesk",
});

const serif = Fraunces({
  subsets: ["latin"],
  variable: "--font-fraunces",
});

export const metadata: Metadata = {
  title: "Preset Web",
  description: "Next.js frontend inside the monorepo with Tailwind CSS and shadcn/ui.",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body className={`${sans.variable} ${serif.variable} font-sans`}>
        <Script src="/runtime-config" strategy="beforeInteractive" />
        {children}
      </body>
    </html>
  );
}