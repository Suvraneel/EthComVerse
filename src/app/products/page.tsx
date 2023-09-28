import { statsData } from '@api/statsData';
import CreatePdtBtn from '@components/Products/CreatePdtBtn';
import ProductTable from '@components/Products/ProductTable';
import StatsCard from '@components/Products/StatsCard';
import { swera } from '@fonts';
import getProducts from '@utils/getProducts';
import { NextPage } from 'next';

const Products: NextPage = async () => {
  const productsData: any = await getProducts();

  return (
    <div className="flex-1 w-full h-full p-10 lg:px-40 overflow-visible flex flex-col justify-start items-start">
      <div className='w-full h-full flex flex-col justify-evenly items-center gap-8 relative'>
        <div className="relative flex place-items-center before:absolute before:h-[50px] before:w-[180px] sm:before:h-[200px] md:before:w-[780px] before:-translate-x-1/2 before:rounded-full before:bg-gradient-radial before:from-white before:to-transparent before:blur-2xl before:content-[''] after:absolute after:-z-20 after:h-[180px] after:w-[200px] sm:after:h-[180px] sm:after:w-[240px] after:translate-x-1/3 after:bg-gradient-conic after:from-sky-200 after:via-blue-200 after:blur-2xl after:content-[''] before:dark:bg-gradient-to-br before:dark:from-transparent before:dark:to-blue-700 before:dark:opacity-10 after:dark:from-sky-900 after:dark:via-[#0141ff] after:dark:opacity-40 before:lg:h-[260px] z-[-1]">
          <h1 className={`text-2xl sm:text-4xl md:text-5xl lg:text-6xl text-white ${swera.className}`}>My Products</h1>
        </div>
        <div className='w-full h-full flex flex-col sm:flex-row justify-end items-center z-0'>
          <CreatePdtBtn />
        </div>
        <div className='w-full grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 justify-evenly items-center gap-4'>
          {
            statsData.map(item => {
              return <StatsCard key={item.label} {...item} />
            })
          }
        </div>
        <ProductTable productsData={productsData} />
      </div>
    </div>
  )
}

export default Products;
