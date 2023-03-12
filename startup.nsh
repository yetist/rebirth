cls
#echo "Press any key to continue..."
#pause

if exist fs0:\rebirth.efi then
  echo "Run rebirth.efi..."
  fs0:\rebirth.efi
endif

echo "Press any key to exit..."
pause
reset -s
