#!/bin/bash

mkdir -p target

mkdir -p cert 

rm target/images.txt
touch target/images.txt
for i in $(ls modules); do 
  echo "Compiling ${i}"
  tag="${i}"
  rm -rf modules/${i}/cert
  cp cert modules/${i}/cert -r
  touch modules/${i}/cert/empty

  docker build -t ${tag} --progress=plain modules/${i}
  echo ${tag} >> target/images.txt
done

echo "Result:" 
cat target/images.txt
