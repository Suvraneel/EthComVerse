import React from 'react'
import Image from 'next/image'

const GenreCard = (props: any) => {
    const { content, isSelected } = props;
    return (
        <div className="py-6 px-5 rounded-xl flex flex-row items-center justify-evenly gap-x-4 border border-cardGray-700 hover:border-gray-700 sm:min-h-[220px] md:min-h-[180px] lg:min-h-min relative group peer-checked:bg-cardGray-900/70 transform hover:scale-105 transition-transform duration-300 peer-checked:shadow-md peer-checked:shadow-cardGray-700/40 peer-checked:ring-offset-cardGray-700">
                <div className={`w-1/2 flex justify-center items-center aspect-square group-hover:hidden relative ${isSelected&&'hidden'}`}>
                    <Image
                        src={`/images/genre/${content.hero}.svg`}
                        alt="Logo"
                        fill={true}
                        style={{ objectFit: "contain" }}
                        loading="lazy"
                    />
                </div>
                <div className={`w-1/2 aspect-square  justify-center items-center group-hover:flex relative ${isSelected?'flex':'hidden'}`}>
                    <Image
                        src={`/images/genre/${content.hero}2.svg`}
                        alt="Logo"
                        fill={true}
                        style={{ objectFit: "contain" }}
                        loading="lazy"
                    />
                </div>
                <div className='z-10'>
                    <div className="w-full flex flex-col gap-1 text-black dark:text-white">
                        <h3 className="font-semibold text-base">
                            {content.title}
                        </h3>
                        <p className="text-gray-700 dark:text-gray-300 text-sm">
                            {content.subTitle}
                        </p>
                    </div>
                </div>
                {content.accent}
        </div>
    )
}

export default GenreCard