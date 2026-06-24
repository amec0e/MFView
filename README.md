# MFView
Mifare view - for viewing mifare bins, json or eml

**Setup:**

Put `85-mfview.conf` in `/etc/lighttpd/conf-enabled/`

Put all other files in `/var/www/html/mfview`

**Set permissions:**

```
sudo chown -R www-data:www-data /var/www/html/mfview
sudo chmod 755 /var/www/html/mfview
sudo chmod 644 /var/www/html/mfview/*
```

**Restart lighttpd:**

`sudo systemctl restart lighttpd`

accessible at `http://YOUR-IP/mfview`

If you do not want to host locally (which can be done on a Pi 4 2GB) you can use the [online version](https://amec0e.github.io/MFView/)

## Special Thanks

- Special thanks to [@Equipter](https://github.com/equipter) for all his help with providing datasheets and dump files to help me test and verify the foundations. <3

This is free to use and modify as you see fit
