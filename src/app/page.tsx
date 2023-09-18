'use client'
import Card from "@components/Card"
import { swera } from "@fonts"
import Image from "next/image"
import { cardsContent } from "@api/cardContent"
import { useEffect } from "react";
import AOS from 'aos';
import 'aos/dist/aos.css';
import { NextPage } from 'next';

const Home: NextPage = () => {
  useEffect(() => {
    AOS.init();
    AOS.refresh();
  }, []);
  return (
    <main className="flex-1 w-full h-full p-4 lg:px-40 overflow-visible pt-10 flex flex-col justify-start items-start sm:gap-8">
      <div className="relative flex place-items-center before:absolute before:h-[50px] before:w-[280px] sm:before:h-[200px] md:before:w-[780px] before:-translate-x-1/2 before:rounded-full before:bg-gradient-radial before:from-white before:to-transparent before:blur-2xl before:content-[''] after:absolute after:-z-20 after:h-[180px] after:w-[200px] sm:after:h-[180px] sm:after:w-[240px] after:translate-x-1/2 after:bg-gradient-conic after:from-sky-200 after:via-blue-200 after:blur-2xl after:content-[''] before:dark:bg-gradient-to-br before:dark:from-transparent before:dark:to-blue-700 before:dark:opacity-10 after:dark:from-sky-900 after:dark:via-[#0141ff] after:dark:opacity-40 before:lg:h-[260px] z-[-1]">
        <h1 className={`text-2xl sm:text-4xl lg:text-6xl text-white  pl-10 md:pl-0 ${swera.className}`}>Token-Gated<br />Creator Economy</h1>
      </div>
      <div className="w-full h-[60vw] sm:h-[70vh] lg:h-[80vh] relative animate-float">
        <Image
          src={'/images/cascade.svg'}
          alt="Logo"
          fill={true}
          style={{objectFit:"contain"}}
          loading="eager"
          priority
          sizes="100vw"
        />
      </div>
      <div className="w-full h-full flex flex-col gap-4">
        <div className="w-full h-full flex flex-row flex-wrap md:flex-nowrap gap-8 justify-between">
          <Card content={cardsContent[0]} />
          <Card content={cardsContent[1]} />
        </div>
        <div className="w-full h-full flex flex-row flex-wrap md:flex-nowrap gap-8 justify-between">
          <Card content={cardsContent[2]} />
          <Card content={cardsContent[3]} />
        </div>
      </div>
    </main>
  )
}

export default Home;
