Image metadata is in images.json. To add a new image, edit images.json and then run
the following cammands as needed to update the pages and create the responsive images.

python image.py -f ClayOwl.jpg process

python gallery.py -t "Susan Frost's Gallery" -p index.html masonary > t
python gallery.py -t "Susan Frost's Gallery" -p gallery.html gallery > t
python gallery.py -t "Prints by Susan Frost" -p prints.html -m Print gallery > t
python gallery.py -t "Drawings by Susan Frost" -p drawings.html -m Pencil gallery > t
python gallery.py -t "Paintings by Susan Frost" -p paintings.html -m Oil gallery > t
python gallery.py -t "Ceramics by Susan Frost" -p ceramics.html -m Clay gallery > t

diff t drawings.html
mv !*

Upload changed html pages to susanafrost.com and make them public
Upload image_hd.jpg, image_med.jpg and image_small.jpg to susanafrost.com/static/img
