"use client";
import Breadcrumb from "@components/Products/New/BreadCrumb";
import Customize from "@components/Products/New/Form/Customize";
import Launchpad from "@components/Products/New/Form/Launchpad";
import LiftOff from "@components/Products/New/Form/LiftOff";
import ChevronLeft from "@icons/ChevronLeft";
import ChevronRight from "@icons/ChevronRight";
import { NextPage } from "next";
import { useState } from "react";
import { useRouter } from "next/navigation";

import {
  useAccount,
  useContractWrite,
  usePrepareContractWrite,
  useNetwork,
} from "wagmi";

import courseABI from "../../../../ABI/course.json";
import courseFactoryABI from "../../../../ABI/courseFactory.json";
import dealClientABI from "../../../../ABI/dealClient.json";

const contractAddresses = {
  dealClient: "0xf2B2081e6827b5b7354C6e3a22f8536f2b353e53",
  courseFactory: "0x2e747c31c57c09BF1c9Ecff6a943bA4CA4B2f8cA",
};

enum Category {
  "Music Royalty",
  "NFT, Collectibles or Art",
  "Newsletter",
  "E book",
  "Course or Tutorial",
  "Digital Good",
  "Podcast",
  "Audiobook",
  "Physical Good",
  "Miscellaneous",
}

const CreateProduct: NextPage = () => {
  const tabItems = ["Launchpad", "Customize", "LiftOff"];
  const [activeTab, setActiveTabState] = useState<number>(0);
  const [numTokens, setNumTokens] = useState<number>(1);
  const [formData, setFormData] = useState({
    name: undefined,
    genre: "Miscellaneous",
    price: undefined,
    description: undefined,
    thumbnail: undefined,
    file_upload: undefined,
    CTA: "Buy Now",
    tags: [],
  });

  const { address, isConnected } = useAccount();

  const router = useRouter();
  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    console.log("Form Data:", formData);
  };

  const prepareFactoryCourseContractWrite = usePrepareContractWrite({
    address: contractAddresses.courseFactory as `0x${string}`,
    abi: courseFactoryABI,
    functionName: "createCourse",
    args: [
      //   URI, // uploaded URI // need to do this
      //   supply, // supply
      //   price, // price
      address, // creator
    ],
  });

  const { data, isLoading, isSuccess, writeAsync } = useContractWrite(
    prepareFactoryCourseContractWrite.config
  );

  // write the function to call the contract
  const callFactory = async () => {
    await writeAsync?.().then((res) => {
      console.log("res", res); // returns contract address ... store it in db
    });
  };

  const prepareCourseContractWrite = usePrepareContractWrite({
    // address: addressOfnewContract
    abi: courseABI,
    functionName: "supportCreator",
    args: [
      numTokens, // number of tokens to buy
    ],
  });

  const {
    data: data2,
    isLoading: isLoading2,
    isSuccess: isSuccess2,
    writeAsync: writeAsync2,
  } = useContractWrite(prepareCourseContractWrite.config);

  const callCourse = async () => {
    await writeAsync2?.().then((res) => {
      console.log("res", res);
      b;
    });
  };

  const setActiveTab = (newTab: number) => {
    if (newTab == 0) setActiveTabState(newTab);
    else if (newTab == 1) {
      formData.name &&
        formData.genre &&
        formData.price &&
        setActiveTabState(newTab);
    } else if (newTab == 2) {
      formData.name &&
        formData.genre &&
        formData.price &&
        formData.description &&
        setActiveTabState(newTab);
    } else if (newTab === 3)
      formData.name &&
        formData.genre &&
        formData.price &&
        formData.description &&
        router.push("/products");
  };

  return (
    <div className="flex-1 w-full h-full p-10 lg:px-40 overflow-visible flex flex-col justify-start items-start">
      <div className="w-full h-full flex flex-col justify-evenly items-center gap-8 relative">
        <div className="relative flex place-items-center before:absolute before:h-[50px] before:w-[180px] sm:before:h-[200px] md:before:w-[780px] before:-translate-x-1/3 before:rounded-full before:bg-gradient-radial before:from-white before:to-transparent before:blur-2xl before:content-[''] after:absolute after:-z-20 after:h-[180px] after:w-[200px] sm:after:h-[180px] sm:after:w-[240px] after:translate-x-1/3 after:bg-gradient-conic after:from-sky-200 after:via-blue-200 after:blur-2xl after:content-[''] before:dark:bg-gradient-to-br before:dark:from-transparent before:dark:to-blue-700 before:dark:opacity-10 after:dark:from-sky-900 after:dark:via-[#0141ff] after:dark:opacity-40 before:lg:h-[260px] z-[-1]">
          <h1 className="text-xl sm:text-2xl md:text-3xl lg:text-4xl text-white">
            What&apos;s brewing in your creative cauldron?
          </h1>
        </div>
        <form
          className="flex w-full h-full flex-col justify-start items-start gap-10"
          onSubmit={handleSubmit}
        >
          <div className="w-full h-fit flex justify-between items-center">
            <Breadcrumb
              activeTab={activeTab}
              setActiveTab={setActiveTab}
              tabItems={tabItems}
            />
            <div className="w-60 h-fit flex flex-row justify-end gap-3">
              <button
                type="button"
                className="w-fit h-fit p-3 flex flex-row items-center justify-evenly gap-2 border border-cardGray-700 hover:border-gray-700 font-normal rounded-lg group"
                onClick={() => setActiveTab(activeTab - 1)}
              >
                <div className="transform group-hover:-translate-x-1 transition-transform">
                  <ChevronLeft className="w-3 h-3" />
                </div>
                Back
              </button>
              <button
                type="submit"
                className="w-fit h-fit p-3 flex flex-row items-center justify-evenly gap-2 border border-cardGray-700 hover:border-gray-700 font-normal rounded-lg group"
                onClick={() => setActiveTab(activeTab + 1)}
              >
                Next
                <div className="transform group-hover:translate-x-1 transition-transform">
                  <ChevronRight className="w-3 h-3" />
                </div>
              </button>
            </div>
          </div>
          {activeTab === 0 && (
            <Launchpad formData={formData} setFormData={setFormData} />
          )}
          {activeTab === 1 && (
            <Customize formData={formData} setFormData={setFormData} />
          )}
          {activeTab === 2 && (
            <LiftOff formData={formData} setFormData={setFormData} />
          )}
        </form>
      </div>
    </div>
  );
};

export default CreateProduct;
