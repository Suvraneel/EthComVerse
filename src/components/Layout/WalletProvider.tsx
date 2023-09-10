'use client'
import Navbar from '@components/Layout/Navbar';
import { ConnectKitProvider, getDefaultConfig } from "connectkit";
import { Suspense } from 'react';
import { WagmiConfig, createConfig } from "wagmi";
import { arbitrum, filecoinCalibration, mainnet, optimism, polygon } from "wagmi/chains";
const walletConnectProjectId = process.env.WALLETCONNECT_PROJECT_ID!;

// Choose which chains you'd like to show
const chains = [mainnet, polygon, optimism, arbitrum, filecoinCalibration];

const config = createConfig(
  getDefaultConfig({
    appName: "Your App Name",
    walletConnectProjectId,
    chains,
  }),
);

const WalletProvider = ({
  children,
}: {
  children: React.ReactNode
}) => {
  return (
    <WagmiConfig config={config}>
      <ConnectKitProvider>
        <Navbar />
        <Suspense>
          {children}
        </Suspense>
      </ConnectKitProvider>
    </WagmiConfig>
  )
}

export default WalletProvider