#!/bin/bash
fpath="$(pwd)/z3nth10n-PHP/"
yes | cp -rf /c/xampp/htdocs/z3nth10n-PHP/ "$fpath"
fpath+=".git"

function php_commit 
{
  read -p "Commit message: " commit_msg
  if [[ ! -z `git --git-dir="$fpath" diff HEAD .gitignore` ]]; then
    git --git-dir="$fpath" rm -rf --cached .
  fi
  git --git-dir="$fpath" add --all
  git --git-dir="$fpath" commit -m "$commit_msg"
  git --git-dir="$fpath" push -u origin master
}

function main_commit 
{
  read -p "Commit message for this repo: " commit_msg
  if [[ ! -z `git diff HEAD .gitignore` ]]; then
    git --git-dir="$fpath" rm -rf --cached .
  fi
  git add --all
  git commit -m "$commit_msg"
  git push -u origin master
}

echo ""
echo "Please select an option:"
echo "  0) Only PHP commit"
echo "  1) Only main commit"
echo "  2) Both commits"
echo ""
read -p "Select an option: " opt

case $opt in
"0")
  php_commit
  ;;
"1")
  main_commit
  ;;
"2")
  php_commit
  main_commit
  ;;
*)
  echo "Unrecognized option, call 'git bind' again."
  ;;
esac