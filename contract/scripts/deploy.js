const hre = require("hardhat");
require("@nomiclabs/hardhat-etherscan");

async function main() {
  const FactoryCourse = await hre.ethers.getContractFactory("FactoryCourse");
  const factoryCourse = await FactoryCourse.deploy("0x4E476F7FB84c785557cDECdbf8CADEbE8EA57C37");
  await factoryCourse.deployed();
  console.log("factoryCourse deployed to:", factoryCourse.address);
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });