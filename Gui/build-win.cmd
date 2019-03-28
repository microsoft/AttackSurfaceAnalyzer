electronize build /target win
del obj\desktop\win\package.json
copy package.json obj\desktop\win\package.json
electron-packager obj\desktop\win --out=bin\AttackSurfaceAnalyzerGUI --overwrite