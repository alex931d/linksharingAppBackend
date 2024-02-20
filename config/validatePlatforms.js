const {PLATFORMS} = require("./platforms");

 const generateMatchExp = (platform) => {
    switch (platform) {
        case PLATFORMS.GITHUB:
            return /^(ftp|http|https):\/\/(?:www\.)?github\.com\/[^ "]+$/;

        case PLATFORMS.FRONTEND_MENTOR:
            return /^(ftp|http|https):\/\/(?:www\.)?frontendmentor\.io\/profile\/[^ "]+$/;

        case PLATFORMS.TWITTER:
            return /^(ftp|http|https):\/\/(?:www\.)?twitter\.com\/[^ "]+$/;

        case PLATFORMS.LINKEDIN:
            return /^(ftp|http|https):\/\/(?:www\.)?linkedin\.com\/in\/[^ "]+$/;

        case PLATFORMS.YOUTUBE:
            return /^(ftp|http|https):\/\/(?:www\.)?youtube\.com\/channel\/[^ "]+$/;

        case PLATFORMS.FACEBOOK:
            return /^(ftp|http|https):\/\/(?:www\.)?facebook\.com\/[^ "]+$/;

        case PLATFORMS.TWITCH:
            return /^(ftp|http|https):\/\/(?:www\.)?twitch\.tv\/[^ "]+$/;

        case PLATFORMS.DEVTO:
            return /^(ftp|http|https):\/\/(?:www\.)?dev\.to\/[^ "]+$/;

        case PLATFORMS.CODEWARS:
            return /^(ftp|http|https):\/\/(?:www\.)?codewars\.com\/users\/[^ "]+$/;

        case PLATFORMS.CODEPEN:
            return /^(ftp|http|https):\/\/(?:www\.)?codepen\.io\/[^ "]+$/;

        case PLATFORMS.FREE_CODE_CAMP:
            return /^(ftp|http|https):\/\/(?:www\.)?freecodecamp\.org\/[^ "]+$/;

        case PLATFORMS.GITLAB:
            return /^(ftp|http|https):\/\/(?:www\.)?gitlab\.com\/[^ "]+$/;

        case PLATFORMS.HASHNODE:
            return /^(ftp|http|https):\/\/(?:www\.)?hashnode\.com\/[^ "]+$/;

        case PLATFORMS.STACK_OVERFLOW:
            return /^(ftp|http|https):\/\/(?:www\.)?stackoverflow\.com\/users\/[^ "]+$/;

        default:
            return null;
    }
};
module.export = { generateMatchExp };