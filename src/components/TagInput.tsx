import { HashtagIcon, PlusIcon, TrashIcon } from '@heroicons/react/24/outline';
import { useRef } from 'react';

const TagInput = (props: any) => {
  const { tags, setTags } = props;
  let tagInputRef = useRef<HTMLInputElement>(null);

  const handleAddTag = () => {
    const newTag: string | undefined = tagInputRef?.current?.value!.trim();
    if (newTag !== '') {
      setTags([...tags, newTag]);
      tagInputRef.current!.value = '';
    }
  };

  const handleRemoveTag = (index: number) => {
    const updatedTags = tags.filter((_: any, i: number) => i !== index);
    setTags(updatedTags);
  };

  return (
    <div className="w-full h-fit flex flex-col justify-start gap-3 items-start">
      <h2 className="text-xl font-bold">Hashtags for visibility</h2>
      <div className="flex flex-row flex-wrap gap-2">
        {tags.map((item: string, index: number) => (
          <div
            key={item}
            className="flex flex-start gap-3 w-fit px-3 py-2 rounded-lg bg-transparent gap-y-2 border border-cardGray-700 hover:border-gray-700">
            <div className="flex flex-row justify-start items-center gap-1">
              <HashtagIcon className='h-4 aspect-square' />
              <h1 className="font-bold">{item}</h1>
            </div>
            <div
              className="cursor-pointer flex justify-center items-center"
              onClick={() => handleRemoveTag(index)}>
              <TrashIcon className='w-6 h-5 hover:text-red-500' />
            </div>
          </div>
        ))}
        <div className="flex flex-row flex-start items-center w-fit px-3 py-2 rounded-lg bg-transparent gap-y-2 border border-cardGray-700 hover:border-gray-700 gap-1">
          <HashtagIcon className='h-4 aspect-square' />
          <input
            type="text"
            name="tags"
            placeholder="tags"
            ref={tagInputRef}
            className="bg-transparent focus:outline-none font-semibold"
            onKeyPress={(event) => {
              if (event.key === 'Enter') {
                event.preventDefault();
                handleAddTag();
              }
            }}
          />
        </div>
        <div
          className="p-2 rounded-lg bg-transparent gap-y-2 border border-cardGray-700 hover:border-gray-700 cursor-pointer"
          onClick={handleAddTag}
        >
          <PlusIcon className='w-6 h-6' />
        </div>
      </div>
    </div>
  );
};

export default TagInput;
