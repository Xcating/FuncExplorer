document.addEventListener('DOMContentLoaded', function() {
    const accordions = document.querySelectorAll('.accordion-item');

    accordions.forEach(function(item) {
        const button = item.querySelector('.accordion-button');
        const body = item.querySelector('.accordion-body');

        // 创建复制按钮
        const copyButton = document.createElement('button');
        copyButton.textContent = '复制';
        copyButton.classList.add('btn', 'btn-sm', 'btn-secondary', 'mt-2');
        copyButton.style.float = 'right';

        // 添加点击事件
        copyButton.addEventListener('click', function() {
            const selectableText = body.querySelectorAll('.selectable');
            let textToCopy = '';
            selectableText.forEach(function(span) {
                textToCopy += span.textContent + '\n';
            });
            navigator.clipboard.writeText(textToCopy).then(function() {
                alert('函数信息已复制到剪贴板！');
            }, function(err) {
                alert('复制失败！');
            });
        });

        // 添加复制按钮到 accordion-body
        body.insertBefore(copyButton, body.firstChild);
    });
});