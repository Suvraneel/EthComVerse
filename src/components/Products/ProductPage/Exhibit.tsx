'use client'
import React from 'react'
import Image
    from 'next/image';
import Hashtag from '@icons/Hashtag';
const Exhibit = (props: any) => {
    const { productsData } = props;
    return (
        <div className="flex-1 w-full h-full p-10 lg:px-40 overflow-visible flex flex-col justify-start items-start">
            <div className='w-full h-full flex flex-col justify-start items-start gap-8'>
                <div className='w-full h-full flex flex-col sm:flex-row justify-start items-start gap-10 md:gap-16'>
                    <div className='h-[80vh] aspect-square flex flex-row justify-center items-center relative rounded-lg border border-cardGray-700 hover:border-gray-700 group'>
                        <Image
                            src={`https://ipfs.moralis.io:2053/ipfs/${productsData?.cover}`}
                            alt="Logo"
                            fill={true}
                            style={{ objectFit: "contain" }}
                            loading="lazy"
                            className='group-hover:scale-110 transition-transform duration-75'
                        />
                    </div>
                    <div className='w-full h-full flex flex-col justify-start items-start gap-16'>
                        <div className='w-full h-full flex flex-col justify-start items-start flex-wrap gap-3'>
                            <h2 className='text-4xl font-medium'>{productsData.title}</h2>
                            <h3 className='font-mono truncate text-neutral-400'>By {productsData.author}</h3>
                            <h1 className='text-5xl font-thin'>$ {productsData.price.toFixed(2)}</h1>
                            <div className="flex flex-row flex-wrap gap-2">
                                {productsData.tags.map((item: string, index: number) => (
                                    <div
                                        key={item}
                                        className="flex flex-start gap-3 w-fit px-3 py-2 rounded-lg bg-transparent gap-y-2 border border-cardGray-700 hover:border-gray-700">
                                        <div className="flex flex-row justify-start items-center gap-1">
                                            <Hashtag className='h-4 aspect-square' />
                                            <h1 className="font-bold">{item}</h1>
                                        </div>
                                    </div>
                                ))}
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    )
}

export default Exhibit