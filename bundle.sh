#!/bin/bash
rm -rf bundle
mkdir bundle
cp *.py bundle/
pip install -r requirements.txt -t ./bundle
pushd bundle
chmod -R 755 *
zip -r ../bundle.zip *
popd
rm -rf bundle
