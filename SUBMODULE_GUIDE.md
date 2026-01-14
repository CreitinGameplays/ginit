# How to turn Ginit into a GitHub Sub-Repository (Submodule)

Follow these steps to decouple `ginit` into its own repository and integrate it back as a Git submodule.

## 1. Create the Remote Repository
Go to GitHub and create a new repository (e.g., `your-username/ginit`). **Do not** initialize it with a README or license.

## 2. Initialize the Local Ginit Repository
From the root of your GeminiOS project:

```bash
cd geminios/ginit
git init
git add .
git commit -m "Initial commit of ginit core"
```

## 3. Push to GitHub
Replace `<YOUR_GITHUB_URL>` with the URL of the repository you created in step 1.

```bash
git remote add origin <YOUR_GITHUB_URL>
git branch -M main
git push -u origin main
```

## 4. Convert to Submodule in GeminiOS
Now you need to remove the local folder from the main GeminiOS repo tracking and add it back as a submodule.

**IMPORTANT: Backup your changes before deleting the folder.**

```bash
# Go back to geminios root
cd ..

# Remove the folder from main git tracking (if it was already tracked)
git rm -r ginit
git commit -m "Removing ginit directory to replace with submodule"

# Add it back as a submodule
git submodule add <YOUR_GITHUB_URL> ginit
git commit -m "Add ginit as a submodule"
git push
```

## 5. Working with Submodules
When someone clones the main repository, they will need to run:
```bash
git submodule update --init --recursive
```

To update ginit to the latest version in the future:
```bash
cd ginit
git pull origin main
cd ..
git add ginit
git commit -m "Update ginit submodule"
```
