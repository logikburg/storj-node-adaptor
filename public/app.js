$(document).ready(function() {
  // All jQuery/JavaScript code will go in here
  console.log('jquery ready');
  var grumpyPicId;

  // Authenticate client
  $('.auth-btn').on('click', function(event) {
    event.preventDefault();
    console.log('Authenticate button clicked');
    $('.auth-result').html('');

    $.ajax({
      method: 'GET',
      url: '/user/authenticate/user-pass'
    }).done(function(result) {
      if (result === 'successful') {
        $('.auth-result')
          .html('Authentication with basic auth successful!')
          .css('color', 'green');
      } else {
        $('.auth-result')
          .html('Authentication failed')
          .css('color', 'red');
      }
    }).error(function(err) {
      handleError('Authentication', '.auth-result', 'html', err);
    });
  });

  // List buckets
  $('.bucket-btn--list').on('click', function(event) {
    event.preventDefault();
    $('.bucket-list').html('');
    console.log('List Buckets button clicked');

    $('.buckets-list')
      .html('Retrieving buckets . . .')
      .css('color', 'orange');

    $.ajax({
      method: 'GET',
      url: '/buckets/list'
    }).done(function(buckets) {
      if (!buckets.length) {
        $('.buckets-list').html('No buckets');
      } else {
        buckets.forEach(function(bucket) {
          $('.buckets-list')
            .html('Buckets: ')
            .css('color', 'black')
          console.log(bucket);
          var bucketList = document.createElement('ul');
          $('.buckets-list').append($(bucketList));
          var bucketItem = document.createElement('li');
          $(bucketItem).html(`Name: ${bucket.name}, id: ${bucket.id}`);
          $(bucketList).append(bucketItem);
        });
      }
    }).error(function(err) {
      handleError('Bucket list', '.buckets-list', 'html', err);
    });
  });

  // Upload file
  $('.files-btn--upload').on('click', function(event) {
    event.preventDefault();

    $('.files-upload').html('');
    console.log('Upload file button clicked');
    $('.files-upload')
      .html('File upload in process . . .')
      .css('color', 'orange');

    $.ajax({
      method: 'GET',
      url: '/files/upload'
    }).done(function(file) {
      console.log('upload', file)
      $('.files-upload')
        .html(`File ${file.filename} uploaded to ${file.bucket}!`)
        .css('color', 'green');
    }).error(function(err) {
      handleError('File Upload', '.files-upload', 'html', err);
    });
  });

  // List files in bucket
  $('.files-btn--list').on('click', function(event) {
    event.preventDefault();
    $('.files-list').html('');
    console.log('List Files in Bucket button clicked');
    $('.files-list')
      .html('Retrieving files . . .')
      .css('color', 'orange');

    $.ajax({
      method: 'GET',
      url: '/files/list'
    }).done(function(bucketsWithFiles) {
      console.log(bucketsWithFiles);
      if (!bucketsWithFiles) {
        $('.files-list').html('No files in buckets');
      } else {
        for (var key in bucketsWithFiles) {
          var bucketName = document.createElement('div');
          $(bucketName)
            .html(`Bucket: ${key}`)
            .css('font-weight', '700');
          $('.files-list')
            .html($(bucketName))
            .css('color', 'black');

          var bucketFilesList = document.createElement('ul');
          $(bucketName).append(bucketFilesList);

          bucketsWithFiles[key].forEach(function(bucketFile) {
            console.log('file', bucketFile);
            var file = document.createElement('li');
            $(file)
              .html(bucketFile.filename)
              .css('font-weight', '300');
            $(bucketFilesList).append(file);
          });
        }
      }
    }).error(function(err) {
      handleError('List Files', '.files-list', 'html', err);
    });
  });

});

function handleError(subject, className, element, err) {
  if (err) {
    console.log(subject + ' error:', err.responseText);
    switch (err.status) {
      case 404:
        $(className)
          [element]('No endpoint! Go build it!')
          .addClass('spacer')
          .css('color', 'red');
        break;
      default:
        var showErr = err.responseText || err.statusText;
        $(className)
          [element](subject + ' error ' + err.responseText)
          .addClass('spacer')
          .css('color', 'red');
    }
  }
}
