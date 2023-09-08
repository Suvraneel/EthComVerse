import { statsData } from '@api/statsData';
import CreatePdtBtn from '@components/Products/CreatePdtBtn';
import ProductTable from '@components/Products/ProductTable';
import StatsCard from '@components/Products/StatsCard';
import { swera } from '@fonts';
import getProducts from '@utils/getProducts';
import { NextPage } from 'next';
import Image from 'next/image';

const Discover: NextPage = async () => {
  const productsData: any = await getProducts()

  return (
    <div className="flex-1 w-full h-full p-10 lg:px-40 overflow-visible flex flex-col justify-start items-start">
        <div className='w-full h-full flex flex-col justify-start items-start gap-8'>
            <div className='w-full h-full flex flex-col sm:flex-row justify-start items-start gap-10 md:gap-16'>
                <div className='h-[80vh] aspect-square flex flex-row justify-center items-center relative rounded-lg border border-cardGray-700 hover:border-gray-700 group'>
                    <Image
                        src={'/images/t-shirt-1.webp'}
                        alt="Logo"
                        fill={true}
                        style={{ objectFit: "contain" }}
                        loading="lazy"
                        className='group-hover:scale-110 transition-transform duration-75'
                    />
                </div>
                <div className='w-full h-full flex flex-col justify-start items-start gap-16'>
                    <div className='w-full h-full flex flex-col justify-start items-start flex-wrap gap-3'>
                        <h2 className='text-4xl font-medium'>{productsData.name}</h2>
                        <h3 className='font-mono truncate text-neutral-400'>By {'0x48574865465864658465846564'}</h3>
                        <h1 className='text-5xl font-thin'>$ {productsData.price}</h1>
                    </div>
                </div>
            </div>
        </div>
    </div>
  )
}

export default Discover;
