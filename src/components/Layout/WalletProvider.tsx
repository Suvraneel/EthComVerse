'use client'
import Navbar from '@components/Layout/Navbar';
import { ConnectKitProvider, getDefaultConfig } from "connectkit";
import { Suspense } from 'react';
import { WagmiConfig, createConfig } from "wagmi";
import { filecoinCalibration } from "wagmi/chains";
const walletConnectProjectId = process.env.WALLETCONNECT_PROJECT_ID!;

// Choose which chains you'd like to show
const chains = [filecoinCalibration];

const config = createConfig(
  getDefaultConfig({
    appName: "EthComVerse",
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
      <ConnectKitProvider
        mode='dark'
        customTheme={customTheme}
        options={{
          embedGoogleFonts: true,
        }}>
        <Navbar />
        <Suspense>
          {children}
        </Suspense>
      </ConnectKitProvider>
    </WagmiConfig>
  )
}

export default WalletProvider


const customTheme = {
  "--ck-font-family": "Inter",
  "--ck-font-weight": "400",
  "--ck-border-radius": "20px",
  "--ck-overlay-backdrop-filter": "blur(2px)",
  "--ck-modal-heading-font-weight": "500",
  "--ck-qr-border-radius": "16px",
  "--ck-connectbutton-font-size": "15px",
  "--ck-connectbutton-color": "#ffffff",
  "--ck-connectbutton-background": "#000000",
  "--ck-connectbutton-background-secondary": "#FFFFFF",
  "--ck-connectbutton-border-radius": "5px",
  "--ck-connectbutton-box-shadow": "0px 0px 16px 10px #ffffff00",
  "--ck-connectbutton-hover-color": "#ffffff",
  "--ck-connectbutton-hover-background": "#000000",
  // "--ck-connectbutton-hover-box-shadow": "1px 1px 20px 10px #47a3ff4f",
  "--ck-connectbutton-active-color": "#ffffff",
  "--ck-connectbutton-active-background": "#3f3f3f",
  "--ck-connectbutton-active-box-shadow": "0 0 0 0 #ffffff",
  "--ck-connectbutton-balance-color": "#373737",
  "--ck-connectbutton-balance-background": "#fff",
  "--ck-connectbutton-balance-box-shadow": "inset 0 0 0 1px #F6F7F9",
  "--ck-connectbutton-balance-hover-background": "#F6F7F9",
  "--ck-connectbutton-balance-hover-box-shadow": "inset 0 0 0 1px #F0F2F5",
  "--ck-connectbutton-balance-active-background": "#F0F2F5",
  "--ck-connectbutton-balance-active-box-shadow": "inset 0 0 0 1px #EAECF1",
  "--ck-primary-button-font-weight": "500",
  "--ck-primary-button-border-radius": "16px",
  "--ck-primary-button-color": "#d4d4d4",
  "--ck-primary-button-background": "#000000",
  "--ck-primary-button-box-shadow": "0 0 0 0 #ffffff",
  "--ck-primary-button-hover-color": "#ffffff",
  "--ck-primary-button-hover-background": "#282828",
  "--ck-primary-button-hover-box-shadow": "0 0 0 0 #ffffff",
  "--ck-primary-button-active-color": "#373737",
  "--ck-primary-button-active-background": "#fdfdfd",
  "--ck-primary-button-active-box-shadow": "0 0 0 0 #ffffff",
  "--ck-secondary-button-font-weight": "500",
  "--ck-secondary-button-border-radius": "16px",
  "--ck-secondary-button-color": "#ffffff",
  "--ck-secondary-button-background": "#111111",
  "--ck-secondary-button-box-shadow": "0 0 0 0 #ffffff",
  "--ck-secondary-button-hover-color": "#ffffff",
  "--ck-secondary-button-hover-background": "#161616",
  "--ck-secondary-button-hover-box-shadow": "0 0 0 0 #ffffff",
  "--ck-secondary-button-active-color": "#373737",
  "--ck-secondary-button-active-background": "#121212",
  "--ck-secondary-button-active-box-shadow": "0 0 0 0 #ffffff",
  "--ck-tertiary-button-font-weight": "500",
  "--ck-tertiary-button-border-radius": "16px",
  "--ck-tertiary-button-color": "#ffffff",
  "--ck-tertiary-button-background": "#000000",
  "--ck-tertiary-button-box-shadow": "0 0 0 0 #ffffff",
  "--ck-tertiary-button-hover-color": "#e1e1e1",
  "--ck-tertiary-button-hover-background": "#181818",
  "--ck-tertiary-button-hover-box-shadow": "0 0 0 0 #ffffff",
  "--ck-tertiary-button-active-color": "#373737",
  "--ck-tertiary-button-active-background": "#F6F7F9",
  "--ck-tertiary-button-active-box-shadow": "0 0 0 0 #ffffff",
  "--ck-modal-box-shadow": "0px 2px 4px 0px #00000005",
  "--ck-overlay-background": "#0625572e",
  "--ck-body-color": "#ffffff",
  "--ck-body-color-muted": "#ffffff",
  "--ck-body-color-muted-hover": "#ededed",
  "--ck-body-background": "#000000",
  "--ck-body-background-transparent": "rgba(255,255,255,0)",
  "--ck-body-background-secondary": "#000000",
  "--ck-body-background-secondary-hover-background": "#e0e4eb",
  "--ck-body-background-secondary-hover-outline": "#4282FF",
  "--ck-body-background-tertiary": "#000000",
  "--ck-body-action-color": "#ffffff",
  "--ck-body-divider": "#ffffff",
  "--ck-body-color-danger": "#ff5050",
  "--ck-body-color-valid": "#2cff4c",
  "--ck-siwe-border": "#F0F0F0",
  "--ck-body-disclaimer-background": "#000000",
  "--ck-body-disclaimer-color": "#ffffff",
  "--ck-body-disclaimer-link-color": "#d8d8d8",
  "--ck-body-disclaimer-link-hover-color": "#ffffff",
  "--ck-tooltip-background": "#000000",
  "--ck-tooltip-background-secondary": "#000000",
  "--ck-tooltip-color": "#ffffff",
  "--ck-tooltip-shadow": "0px 2px 10px 0 #00000014",
  "--ck-dropdown-button-color": "#999999",
  "--ck-dropdown-button-box-shadow": "0 0 0 1px rgba(0,0,0,0.01), 0px 0px 7px rgba(0, 0, 0, 0.05)",
  "--ck-dropdown-button-background": "#fff",
  "--ck-dropdown-button-hover-color": "#8B8B8B",
  "--ck-dropdown-button-hover-background": "#F5F7F9",
  "--ck-qr-dot-color": "#ffffff",
  "--ck-qr-background": "#000000",
  "--ck-qr-border-color": "#3f3f3f",
  "--ck-focus-color": "#1A88F8",
  "--ck-spinner-color": "#1A88F8",
  "--ck-copytoclipboard-stroke": "#CCCCCC",
  "--ck-recent-badge-color": "#ffffff",
  "--ck-recent-badge-background": "#000000",
  "--ck-recent-badge-border-radius": "32px"
}