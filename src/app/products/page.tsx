'use client'
import { useState } from 'react';
import { NextPage } from 'next'
import { statsData } from '@api/statsData';
import { productsData } from '@api/productData';
import StatsCard from '@components/Products/StatsCard';
import { swera } from '@fonts';
import ProductRow from '@components/Products/ProductRow';
import CreatePdtBtn from '@components/Products/CreatePdtBtn';

const Products: NextPage = () => {
  const [baseIdx, setBaseIdx] = useState(0);
  const columns = [
    { id: "position", label: "Sl No." },
    { id: "title", label: "Title" },
    { id: "price", label: "Price" },
    { id: "status", label: "Status" },
  ];
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
        <div className='w-full h-full flex flex-col justify-start items-center gap-0 relative  border border-cardGray-700 rounded-xl bg-black text-white'>
          <table className='w-full h-full flex md:table overflow-auto table-auto text-sm text-left '>
            <thead className="hidden md:table-header-group text-lg">
              <tr className='table-row text-neutral-400 underline underline-offset-4 font-medium tracking-wider text-base'>
                {columns.map((column) => (
                  <th
                    scope="col"
                    className="table-cell text-left px-6 py-2"
                    key={column.id}
                  >
                    {column.label}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody className='w-full group'>
              {productsData.slice(baseIdx, baseIdx + 5).map((item: any, idx: any) => {
                return <ProductRow key={item._id} idx={baseIdx + idx} {...item} />
              })}
            </tbody>
          </table>
          <div className='w-full flex flex-row justify-between items-center px-10 py-2 gap-5 border-t border-cardGray-700'>
            <div className='w-fit h-full flex flex-row justify-start items-center'>
              <h3 className='text-base'>Showing {baseIdx} to {Math.min(baseIdx + 5, productsData.length)} of {productsData.length} entries</h3>
            </div>
            <div className='w-fit h-full flex flex-row justify-end items-center divide-x-2'>
              <div
                className='w-fit h-full flex flex-row justify-around gap-2 items-center px-4'
                onClick={() => baseIdx >= 5 && setBaseIdx(baseIdx - 5)}>
                {/* <FontAwesomeIcon icon={faChevronCircleLeft} className='h-6 w-6' /> */}
                <h5 className='text-base'>Newer</h5>
              </div>
              <div
                className='w-fit h-full flex flex-row justify-around gap-2 items-center px-4'
                onClick={() => baseIdx < productsData.length - 5 && setBaseIdx(baseIdx + 5)}>
                <h5 className='text-base'>Older</h5>
                {/* <FontAwesomeIcon icon={faChevronCircleRight} className='h-6 w-6' /> */}
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}

export default Products;
