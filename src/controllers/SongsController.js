// controllers/songController.js
const { PrismaClient } = require('@prisma/client');
const prisma = new PrismaClient();
const path = require('path');
const fs = require('fs');

function convertBigInt(obj, parentKey = '') {
  if (typeof obj === 'bigint') {
    return obj.toString();
  } else if (obj instanceof Date) {
    // Only date for specific keys like 'dob'
    if (['dob', 'date_of_birth', 'birth_date','from_date','to_date'].includes(parentKey)) {
      return obj.toISOString().split('T')[0];
    } else {
      return obj.toISOString(); // full datetime for created_at, updated_at etc.
    }
  } else if (Array.isArray(obj)) {
    return obj.map(item => convertBigInt(item));
  } else if (obj !== null && typeof obj === 'object') {
    const newObj = {};
    for (const key in obj) {
      newObj[key] = convertBigInt(obj[key], key);
    }
    return newObj;
  }

  return obj;
}
exports.filterSongs = async (req, res) => {
  try {
    const { language_id, song_type, organization_id, search, page } = req.body;
    const user = req.user; // assume auth middleware sets req.user
    const currentPage = parseInt(page) || 1;
    const limit = 10;
    const skip = (currentPage - 1) * limit;

    // Determine lyric_id
    let lyric_id = (language_id && [2, 3].includes(Number(language_id))) ? 1 : 0;
    if (user.org_id == 1 && Number(language_id) === 3) {
      lyric_id = 0;
    }

    let whereClause = {};
    let orderBy = {};

    if (song_type === '2') {

       // console.log('Filtering My Songs');
      // My Songs
      whereClause = {
        ...(user.role === 1
          ? organization_id && organization_id !== '0'
            ? { org_id: Number(organization_id) }
            : {}
          : { org_id: user.org_id })
      };

      // Search filter
if (search && search.trim() !== '') {
  whereClause.songs = {
    OR: [
      { title: { contains: search } },
      { author: { contains: search } },
      { song_id: isNaN(Number(search)) ? undefined : Number(search) }
    ].filter(Boolean) // remove undefined conditions
  };
}


      // Language filter
      if (language_id && language_id != 'All Languages') {
        whereClause.songs = {
          ...whereClause.songs,
          language_id: Number(language_id),
          lyric_id
        };
      }

      orderBy = { song_number: 'asc' };

      // Fetch data
      const [totalCount, data] = await Promise.all([
        prisma.my_songs.count({ where: whereClause }),
        prisma.my_songs.findMany({
          where: whereClause,
          include: {
            songs:true,
            origanisation: true
          },
          orderBy,
          skip,
          take: limit
        })
      ]);


       const settings = await prisma.settings.findMany({
              where: { org_id: user.org_id },
              orderBy: { id: 'desc' }
            });

      return res.json({
        data:convertBigInt(data),
        totalCount,
        currentPage,
        totalPages: Math.ceil(totalCount / limit),
        settings: convertBigInt(settings)
      });
    } else {
        //console.log('Filtering Default Songs');
      // Default Songs
      whereClause = {
        OR: [
          { org_id: null },
          {
            org_id: { not: null },
            copyright: 'no'
          }
        ]
      };

      // Search filter
      if (search && search.trim() !== '') {
        whereClause.AND = [
          {
            OR: [
              { title: { contains: search } },
              { author: { contains: search } },
              {  song_id: isNaN(Number(search)) ? undefined : Number(search)}
            ]
          }
        ];
      }

      // Language filter
      if (language_id && language_id != 'All Languages') {
        whereClause.AND = [
          ...(whereClause.AND || []),
          { language_id: Number(language_id) },
          { lyric_id }
        ];
      }

      orderBy = { song_id: 'asc' };

      const [totalCount, data] = await Promise.all([
        prisma.songs.count({ where: whereClause }),
        prisma.songs.findMany({
          where: whereClause,
          include: {
            origanisation: true
          },
          orderBy,
          skip,
          take: limit
        })
      ]);

      return res.json({
        data:convertBigInt(data),
        currentPage,
        totalCount,
        totalPages: Math.ceil(totalCount / limit)
      });
    }
  } catch (error) {
    console.error('Error filtering songs:', error);
    return res.status(500).json({ error: 'Server error' });
  }
};


exports.getSongNumber = async (req, res) => {
  try {
    const user = req.user; // assuming you already have authenticated user in req.user
    let index_number = 1;

    if (user.role === 1) {
      // Count songs where org_id is null OR (org_id is not null and copyright = 'no')
      const songCount = await prisma.songs.count({
        where: {
          OR: [
            { org_id: null },
            {
              AND: [
                { org_id: { not: null } },
                { copyright: 'no' }
              ]
            }
          ]
        }
      });

      index_number = songCount ? songCount + 1 : 1;

    } else {
      // Get last song_number for this org
      const lastSong = await prisma.my_songs.findFirst({
        where: { org_id: user.org_id },
        orderBy: { song_number: 'desc' },
        select: { song_number: true }
      });

      index_number = lastSong ? lastSong.song_number + 1 : 1;
    }

    return res.json({ index_number });

  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: 'Server error' });
  }
};


exports.addSong = async (req, res) => {
  try {
    const user = req.user; // authenticated user from middleware
    const {
      language,
      songnumber,
      song,
      title,
      author,
      eng_lyrics,
      eng_title,
      copyright,
    } = req.body;

    // Determine lyric_id
    let lyric_id = 0;
    if (language === 2) {
      lyric_id = 1;
    } else if (language === 3) {
      lyric_id = 1;
    }

    // Determine org_id
    let org_id = null;
    if (user.role !== 1) {
      org_id = user.org_id;
    }


    // Create song
    const createSong = await prisma.songs.create({
      data: {
        song_id: songnumber,
        song: song,
        title,
        author,
        status: 1,
        org_id,
        language_id: Number(language),
        lyric_id,
        eng_lyrics,
        eng_title,
        copyright
      }
    });

    // Create MySong if not role 1
    if (user.role !== 1) {
      await prisma.my_songs.create({
        data: {
          sid: createSong.id,
          song_number: songnumber,
          org_id
        }
      });
    }

    return res.json({
      success: true,
      message: 'New song inserted successfully!',
      data: convertBigInt(createSong)
    });

  } catch (error) {
    console.error(error);
    return res.status(500).json({
      success: false,
      message: 'Error creating song',
      error: error.message
    });
  }
};



exports.SongDetails = async (req, res) => {
  try {
    const user = req.user; // authenticated user
    const songId = req.body.id;

    let checkexistornot = null;

    if (user.role !== 1) {
      checkexistornot = await prisma.my_songs.findFirst({
        where: {
          sid: songId,
          org_id: user.org_id
        },
        include: {
          songs: true
        }
      });
    }

    const songDetails =
      checkexistornot?.song ||
      (await prisma.songs.findUnique({
        where: { id: songId }
      }));

    const song = {
      id: songDetails?.id ?? null,
      org_id: checkexistornot
        ? checkexistornot.org_id
        : songDetails?.org_id ?? null,
      language_id: songDetails?.language_id ?? null,
      song_id: checkexistornot
        ? checkexistornot.song_number
        : songDetails?.song_id ?? null,
      song: songDetails?.song ?? null,
      eng_lyrics: songDetails?.eng_lyrics ?? null,
      eng_title: songDetails?.eng_title ?? null,
      copyright: songDetails?.copyright ?? null,
      title: songDetails?.title ?? null,
      author: songDetails?.author ?? null
    };

    return res.json({
      success: true,
      data: convertBigInt(song)
    });
  } catch (error) {
    console.error(error);
    return res.status(500).json({
      success: false,
      message: 'Error fetching song details',
      error: error.message
    });
  }
};


// Controller function
exports.updateSong = async (req, res) => {
  try {
    const {
      id,
      song,
      title,
      author,
      language,
      copyright,
      eng_title,
      eng_lyrics
    } = req.body;

    // Update song using Prisma
    const updateSong = await prisma.songs.update({
      where: { id: parseInt(id) },
      data: {
        song: song,
        title,
        author,
        language_id: parseInt(language),
        copyright,
        eng_title,
        eng_lyrics
      }
    });

    // For redirect-like behavior
    res.json({
      message: "Song updated successfully!",
      song: convertBigInt(updateSong)
    });

  } catch (error) {
    console.error("Error updating song:", error);
    res.status(500).json({ error: "Something went wrong while updating the song." });
  }
};


// songstatuschange
exports.deleteSong = async (req, res) => {
  try {
    const { id } = req.body;

    await prisma.songs.update({
      where: { id: Number(id) },
      data: {
        status:2,
        updated_at: new Date()
      }
    });

    return res.json({
      success: true
    });

  } catch (error) {
    console.error("Error updating song status:", error);
    return res.status(500).json({
      success: false,
      message: "Failed to update song status."
    });
  }
};


exports.updateSongsSettings = async (req, res) => {
  try {
    const { settingId, display_type } = req.body;

    await prisma.settings.update({
      where: { id: Number(settingId) },
      data: { songs_display:display_type }
    });

    return res.json({
      success: true,
      statusCode: 200
    });

  } catch (error) {
    console.error('Error updating faith statement:', error);
    return res.status(500).json({
      success: false,
      statusCode: 500,
      message: 'Internal server error'
    });
  }
};


// controllers/songsController.js



exports.importSongsPdf = async (req, res) => {
  try {
    const file = req.file;
    const { title } = req.body;

    if (!file) {
      return res.status(400).json({ success: false, message: 'PDF file is required' });
    }

    const user = req.user;
    if (!user || !user.org_id) {
      return res.status(403).json({ success: false, message: 'Authentication required with org_id' });
    }

    const relativeDir = `organizations/${user.org_id}/songs`;
    const destinationPath = path.join(__dirname, '../public', relativeDir);

    if (!fs.existsSync(destinationPath)) {
      fs.mkdirSync(destinationPath, { recursive: true });
    }

    const fileName = `${Date.now()}_${file.originalname}`;
    const filePath = path.join(destinationPath, fileName);

    // Write from memory buffer to disk
    fs.writeFileSync(filePath, file.buffer);

    const fileUrl =`${req.protocol}://${req.get('host')}/public/${relativeDir}/${fileName}`;

    await prisma.songs_pdf_files.create({
      data: {
        title: title,
        song_url: fileUrl,
        org_id: user.org_id,
        updated_at: new Date(),
      }
    });

    return res.json({
      success: true,
      message: 'PDF file uploaded and record saved successfully!'
    });

  } catch (error) {
    console.error('Error uploading PDF:', error);
    return res.status(500).json({
      success: false,
      message: 'Internal server error'
    });
  }
};




exports.getPdfSongs = async (req, res) => {
  try {
    const user = req.user; // populated by authentication middleware

    if (!user || !user.org_id) {
      return res.status(403).json({
        success: false,
        message: 'Authentication required with org_id'
      });
    }

    const pdfFiles = await prisma.songs_pdf_files.findMany({
      where: { org_id: user.org_id }
    });

    return res.json({
      success: true,
      data: pdfFiles
    });

  } catch (error) {
    console.error('Error fetching PDF songs:', error);
    return res.status(500).json({
      success: false,
      message: 'Internal server error'
    });
  }
};




exports.addSongsToOrg = async (req, res) => {
  try {
    const { songs, status } = req.body;
    const userOrgId = req.user.org_id; // Assuming you have auth middleware setting req.user

    // Split the checked song IDs (Laravel did explode)
//    const songIds = checkedIds.split(',');

    for (let i = 0; i < songs.length; i++) {
      const songId = parseInt(songs[i], 10);

      if (status === 1) {
        // Add song logic
        const existingSong = await prisma.my_songs.findFirst({
          where: {
            sid: songId,
            org_id: userOrgId
          }
        });

        if (!existingSong) {
          // Get the highest song_number
          const latestSong = await prisma.my_songs.findFirst({
            where: { org_id: userOrgId },
            orderBy: { song_number: 'desc' }
          });

          const index_number = latestSong ? latestSong.song_number + 1 : 1;

          await prisma.my_songs.create({
            data: {
              sid: songId,
              song_number: index_number,
              org_id: userOrgId
            }
          });
        }
      } 
      else if (status === 2) {
        // Remove song logic
        await prisma.my_songs.deleteMany({
          where: {
            sid: songId,
            org_id: userOrgId
          }
        });
      }
    }

    return res.json({
      success: true,
      statusCode: 200
    });
  } catch (error) {
    console.error(error);
    return res.status(500).json({
      success: false,
      statusCode: 500,
      message: 'Server error',
      error: error.message
    });
  }
};

